#[cfg(feature = "no_std")]
use alloc::format;
#[cfg(feature = "no_std")]
use alloc::string::String;
#[cfg(feature = "no_std")]
use alloc::string::ToString;

#[cfg(feature = "no_std")]
use das_types::{constants::*, packed, prelude::*};
#[cfg(feature = "std")]
use das_types_std::{constants::*, packed, prelude::*};

use crate::error::ASTError;
use crate::types::*;
use crate::util::*;

fn assert_param_length(key: String, length: usize, expected_length: usize) -> Result<(), ASTError> {
    if length != expected_length {
        return Err(ASTError::ParamLengthError {
            key,
            expected_length: expected_length.to_string(),
            length: format!("it is {}", length),
        });
    }

    Ok(())
}

fn assert_param_length_gte(key: String, length: usize, expected_length: usize) -> Result<(), ASTError> {
    if length < expected_length {
        return Err(ASTError::ParamLengthError {
            key,
            expected_length: format!(">= {}", expected_length),
            length: format!("it is {}", length),
        });
    }

    Ok(())
}

fn assert_param_type_equal(key: String, val_1: &Value, val_2: &Value) -> Result<(), ASTError> {
    if val_1.get_type() != val_2.get_type() {
        return Err(ASTError::ParamTypeMismatch {
            key,
            types: format!("{}, {}", val_1.get_type(), val_2.get_type()),
        });
    }

    Ok(())
}

macro_rules! assert_and_get_return {
    ($key: expr, $value: expr, $value_type: ident) => {
        match $value {
            Value::$value_type(val) => val,
            _ => {
                return Err(ASTError::ReturnTypeError {
                    key: $key.to_string(),
                    type_: ValueType::$value_type,
                })
            }
        }
    };
}

pub fn match_rule_with_account_chars<'a>(
    rules: &'a [SubAccountRule],
    account_chars: packed::AccountCharsReader,
    account: &str,
) -> Result<Option<&'a SubAccountRule>, ASTError> {
    for (i, rule) in rules.iter().enumerate() {
        if rule.status == SubAccountRuleStatus::Off {
            continue;
        }

        match rule.ast {
            Expression::Function(_) | Expression::Operator(_) => {}
            _ => {
                return Err(ASTError::FunctionOrOperatorRequired {
                    key: format!("rules[{}].ast", i),
                })
            }
        }

        let value = handle_expression(format!("rules[{}].ast", i), &rule.ast, account_chars, account)?;
        let ret = assert_and_get_return!(format!("rules[{}]", i), value, Bool);

        if ret {
            return Ok(Some(rule));
        }
    }

    Ok(None)
}

fn handle_expression(
    key: String,
    ast: &Expression,
    account_chars: packed::AccountCharsReader,
    account: &str,
) -> Result<Value, ASTError> {
    let value = match ast {
        Expression::Operator(operator) => handle_operator(key, operator, account_chars, account)?,
        Expression::Function(function) => handle_function(key, function, account_chars, account)?,
        Expression::Variable(variable) => handle_variable(key, variable, account_chars, account)?,
        Expression::Value(value) => value.value.clone(),
        // _ => todo!()
    };

    Ok(value)
}

fn handle_operator(
    key: String,
    operator: &OperatorExpression,
    account_chars: packed::AccountCharsReader,
    account: &str,
) -> Result<Value, ASTError> {
    macro_rules! compare_values {
        ($method: ident) => {{
            assert_param_length(key.clone() + ".expressions", operator.expressions.len(), 2)?;

            let left = handle_expression(
                key.clone() + ".expressions[0]",
                &operator.expressions[0],
                account_chars,
                account,
            )?;
            let right = handle_expression(
                key.clone() + ".expressions[1]",
                &operator.expressions[1],
                account_chars,
                account,
            )?;

            assert_param_type_equal(key.clone() + ".expressions", &left, &right)?;
            left.$method(&right).map_err(|err| ASTError::OperatorExecuteFailed {
                key,
                operator: operator.symbol.to_string(),
                reason: err.to_string(),
            })?
        }};
    }

    let ret = match operator.symbol {
        SymbolType::And => {
            assert_param_length_gte(key.clone() + ".expressions", operator.expressions.len(), 2)?;

            let mut ret = true;
            for (i, expression) in operator.expressions.iter().enumerate() {
                let value = handle_expression(
                    format!("{}.expressions[{}]", key, i),
                    expression,
                    account_chars,
                    account,
                )?;
                match value {
                    Value::Bool(val) => {
                        if !val {
                            ret = false;
                        }
                    }
                    _ => {
                        return Err(ASTError::ReturnTypeError {
                            key: format!("{}.expressions[{}]", key, i),
                            type_: ValueType::Bool,
                        })
                    }
                }
            }

            ret
        }
        SymbolType::Or => {
            assert_param_length_gte(key.clone() + ".expressions", operator.expressions.len(), 2)?;

            let mut ret = false;
            for (i, expression) in operator.expressions.iter().enumerate() {
                let value = handle_expression(
                    format!("{}.expressions[{}]", key, i),
                    expression,
                    account_chars,
                    account,
                )?;
                match value {
                    Value::Bool(val) => {
                        if val {
                            ret = true;
                        }
                    }
                    _ => {
                        return Err(ASTError::ReturnTypeError {
                            key: format!("{}.expressions[{}]", key, i),
                            type_: ValueType::Bool,
                        })
                    }
                }
            }

            ret
        }
        SymbolType::Not => {
            assert_param_length(key.clone() + ".expressions", operator.expressions.len(), 1)?;

            let value = handle_expression(
                key.clone() + ".expressions[0]",
                &operator.expressions[0],
                account_chars,
                account,
            )?;
            match value {
                Value::Bool(val) => !val,
                _ => {
                    return Err(ASTError::ReturnTypeError {
                        key: key.clone() + ".expressions[0]",
                        type_: ValueType::Bool,
                    })
                }
            }
        }
        SymbolType::Equal => compare_values!(equal),
        SymbolType::Gt => compare_values!(greater_than),
        SymbolType::Gte => compare_values!(greater_than_or_equal),
        SymbolType::Lt => compare_values!(less_than),
        SymbolType::Lte => compare_values!(less_than_or_equal),
        // _ => todo!(),
    };

    Ok(Value::Bool(ret))
}

fn handle_function(
    key: String,
    function: &FunctionExpression,
    account_chars: packed::AccountCharsReader,
    account: &str,
) -> Result<Value, ASTError> {
    macro_rules! call_fn {
        ($fn_name: ident, $arg_len: expr) => {{
            assert_param_length(key.clone() + ".arguments", function.arguments.len(), $arg_len)?;
            $fn_name(key.clone(), &function.arguments, account_chars, account)
        }};
    }

    let ret = match function.name {
        FnName::IncludeChars | FnName::IncludeWords => call_fn!(include_chars, 2),
        FnName::OnlyIncludeCharset => call_fn!(only_include_charset, 2),
        FnName::InList => call_fn!(in_list, 2),
    }
    .map_err(|err| ASTError::FunctionExecuteFailed {
        key: key.clone(),
        name: function.name.to_string(),
        reason: err.to_string(),
    })?;

    if ret.get_type() != ValueType::Bool {
        return Err(ASTError::ReturnTypeError {
            key,
            type_: ValueType::Bool,
        });
    }

    Ok(ret)
}

fn handle_variable(
    key: String,
    variable: &VariableExpression,
    account_chars: packed::AccountCharsReader,
    account: &str,
) -> Result<Value, ASTError> {
    let ret = match variable.name {
        VarName::Account => Value::String(account.to_string()),
        VarName::AccountChars => {
            let mut string_vec = vec![];
            for (i, char) in account_chars.iter().enumerate() {
                let char = String::from_utf8(char.bytes().raw_data().to_owned()).map_err(|_| {
                    ASTError::ParseUtf8StringFailed {
                        key: format!("{}[{}]", key, i),
                    }
                })?;
                string_vec.push(char);
            }

            Value::StringVec(string_vec)
        }
        VarName::AccountLength => Value::Uint32(account_chars.len() as u32), // _ => todo!(),
    };

    Ok(ret)
}

fn include_chars(
    key: String,
    arguments: &[Expression],
    account_chars: packed::AccountCharsReader,
    account: &str,
) -> Result<Value, ASTError> {
    let account_chars_value = handle_expression(key.clone() + ".arguments[0]", &arguments[0], account_chars, account)?;
    let chars = handle_expression(key.clone() + ".arguments[1]", &arguments[1], account_chars, account)?;

    match (account_chars_value, chars) {
        (Value::String(account), Value::StringVec(chars)) => {
            for char in chars.iter() {
                if account.contains(char) {
                    return Ok(Value::Bool(true));
                }
            }

            Ok(Value::Bool(false))
        }
        _ => Err(ASTError::ValueTypeMismatch),
    }
}

fn only_include_charset(
    key: String,
    arguments: &[Expression],
    account_chars: packed::AccountCharsReader,
    account: &str,
) -> Result<Value, ASTError> {
    let charset = handle_expression(key.clone() + ".arguments[1]", &arguments[1], account_chars, account)?;

    let expected_charset = match charset {
        Value::CharsetType(charset) => charset,
        _ => return Err(ASTError::ValueTypeMismatch),
    };

    for item in account_chars.iter() {
        let charset_index = u32::from(item.char_set_name());
        let charset = CharSetType::try_from(charset_index).map_err(|_| ASTError::UndefinedCharSetType {
            key: "".to_string(),
            type_: charset_index,
        })?;

        if expected_charset != charset {
            return Ok(Value::Bool(false));
        }
    }

    Ok(Value::Bool(true))
}

fn in_list(
    key: String,
    arguments: &[Expression],
    account_chars: packed::AccountCharsReader,
    account: &str,
) -> Result<Value, ASTError> {
    let account_var = handle_expression(key.clone() + ".arguments[0]", &arguments[0], account_chars, account)?;

    let account_list = handle_expression(key.clone() + ".arguments[1]", &arguments[1], account_chars, account)?;

    match (account_var, account_list) {
        (Value::String(account), Value::BinaryVec(account_list)) => {
            let hash = blake2b_256(account);
            let account_id = hash[0..20].to_vec();
            Ok(Value::Bool(account_list.contains(&account_id)))
        }
        _ => Err(ASTError::ValueTypeMismatch),
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;
    use das_types_std::types;
    use crate::util;

    #[test]
    fn playground() {
        let rules_json = json!([
            {
                "index": 0,
                "name": "Price of 1 Charactor Emoji DID",
                "note": "",
                "price": 100_000_000,
                "status": 1,
                "ast": {
                    "type": "operator",
                    "symbol": "and",
                    "expressions": [
                        {
                            "type": "operator",
                            "symbol": "==",
                            "expressions": [
                                {
                                    "type": "variable",
                                    "name": "account_length",
                                },
                                {
                                    "type": "value",
                                    "value_type": "uint32",
                                    "value": 1,
                                },
                            ],
                        },
                        {
                            "type": "function",
                            "name": "only_include_charset",
                            "arguments": [
                                {
                                    "type": "variable",
                                    "name": "account_chars",
                                },
                                {
                                    "type": "value",
                                    "value_type": "charset_type",
                                    "value": "Emoji",
                                }
                            ],
                        }
                    ]
                }
            }
        ]);

        let rules = util::json_to_sub_account_rules(String::new(), &rules_json).unwrap();

        let mut dummy_account_chars_builder = packed::AccountChars::new_builder();
        dummy_account_chars_builder = dummy_account_chars_builder.push(packed::AccountChar::default());
        let dummy_account_chars = dummy_account_chars_builder.build();
        let dummy_account = "";

        let ret = match_rule_with_account_chars(&rules, dummy_account_chars.as_reader(), dummy_account);
        println!("return: {:?}", ret);
        if let Err(err) = ret.as_ref() {
            println!("error msg: {:?}\n", err.to_string());
        }

        assert!(ret.is_ok());
    }

    #[test]
    fn test_ast_not_function_or_operator() {
        let rules = vec![SubAccountRule {
            index: 0,
            name: "".to_string(),
            note: "".to_string(),
            price: 0,
            status: SubAccountRuleStatus::On,
            ast: Expression::Value(ValueExpression {
                value_type: ValueType::Bool,
                value: Value::Bool(true),
            }),
        }];

        let ret = match_rule_with_account_chars(&rules, packed::AccountChars::default().as_reader(), "");
        assert!(ret.is_err());
        assert!(matches!(ret.unwrap_err(), ASTError::FunctionOrOperatorRequired { .. }));
    }

    #[test]
    fn test_disabled_rule_skipping() {
        let rules = vec![SubAccountRule {
            index: 0,
            name: "".to_string(),
            note: "".to_string(),
            price: 0,
            status: SubAccountRuleStatus::Off,
            ast: Expression::Operator(OperatorExpression {
                symbol: SymbolType::And,
                expressions: vec![
                    Expression::Value(ValueExpression {
                        value_type: ValueType::Bool,
                        value: Value::Bool(true),
                    }),
                    Expression::Value(ValueExpression {
                        value_type: ValueType::Bool,
                        value: Value::Bool(true),
                    }),
                ],
            }),
        },
        SubAccountRule {
            index: 1,
            name: "".to_string(),
            note: "".to_string(),
            price: 0,
            status: SubAccountRuleStatus::On,
            ast: Expression::Operator(OperatorExpression {
                symbol: SymbolType::And,
                expressions: vec![
                    Expression::Value(ValueExpression {
                        value_type: ValueType::Bool,
                        value: Value::Bool(true),
                    }),
                    Expression::Value(ValueExpression {
                        value_type: ValueType::Bool,
                        value: Value::Bool(true),
                    }),
                ],
            }),
        }];

        let ret = match_rule_with_account_chars(&rules, packed::AccountChars::default().as_reader(), "").unwrap();
        assert!(ret.is_some());

        // rules[0] is disabled, so the matched rule should be rules[1]
        let rule = ret.unwrap();
        assert_eq!(1, rule.index);
    }

    #[test]
    fn test_function_include_chars() {
        let key = String::from(".");
        let arguments = vec![
            Expression::Variable(VariableExpression {
                name: VarName::Account,
            }),
            Expression::Value(ValueExpression {
                value_type: ValueType::StringVec,
                value: Value::StringVec(vec!["🌈".to_string(), "✨".to_string()]),
            }),
        ];
        let account_chars = packed::AccountChars::default();

        let false_account = "xxxxx";
        let true_account = "xxxx🌈";

        let ret = include_chars(key.clone(), &arguments, account_chars.as_reader(), false_account).unwrap();
        assert!(matches!(ret, Value::Bool(false)));

        let ret = include_chars(key.clone(), &arguments, account_chars.as_reader(), true_account).unwrap();
        assert!(matches!(ret, Value::Bool(true)));


        let arguments = vec![
            Expression::Variable(VariableExpression {
                name: VarName::Account,
            }),
            Expression::Value(ValueExpression {
                value_type: ValueType::StringVec,
                value: Value::StringVec(vec!["uni".to_string(), "meta".to_string()]),
            }),
        ];

        let false_account = "xxxxxxx";
        let true_account = "metaverse";

        let ret = include_chars(key.clone(), &arguments, account_chars.as_reader(), false_account).unwrap();
        assert!(matches!(ret, Value::Bool(false)));

        let ret = include_chars(key.clone(), &arguments, account_chars.as_reader(), true_account).unwrap();
        assert!(matches!(ret, Value::Bool(true)));
    }

    #[test]
    fn test_only_include_charset() {
        let key = String::from(".");
        let arguments = vec![
            Expression::Variable(VariableExpression {
                name: VarName::AccountChars,
            }),
            Expression::Value(ValueExpression {
                value_type: ValueType::CharsetType,
                value: Value::CharsetType(CharSetType::Digit),
            }),
        ];
        let false_account_chars: packed::AccountChars = vec![
            types::AccountChar { char_set_type: CharSetType::Digit, char: String::new() },
            types::AccountChar { char_set_type: CharSetType::Digit, char: String::new() },
            types::AccountChar { char_set_type: CharSetType::Digit, char: String::new() },
            types::AccountChar { char_set_type: CharSetType::Emoji, char: String::new() },
        ].into();
        let account = "111✨";

        let ret = only_include_charset(key.clone(), &arguments, false_account_chars.as_reader(), account).unwrap();
        assert!(matches!(ret, Value::Bool(false)));

        let true_account_chars: packed::AccountChars = vec![
            types::AccountChar { char_set_type: CharSetType::Digit, char: String::new() },
            types::AccountChar { char_set_type: CharSetType::Digit, char: String::new() },
            types::AccountChar { char_set_type: CharSetType::Digit, char: String::new() },
            types::AccountChar { char_set_type: CharSetType::Digit, char: String::new() },
        ].into();
        let account = "1111";

        let ret = only_include_charset(key.clone(), &arguments, true_account_chars.as_reader(), account).unwrap();
        assert!(matches!(ret, Value::Bool(true)));
    }
}
