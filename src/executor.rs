#[cfg(feature = "no_std")]
use alloc::string::ToString;
#[cfg(feature = "no_std")]
use alloc::string::String;
#[cfg(feature = "no_std")]
use alloc::format;

#[cfg(feature = "no_std")]
use das_types::{constants::*, packed, prelude::*};
#[cfg(feature = "std")]
use das_types_std::{constants::*, packed, prelude::*};

use crate::error::ASTError;
use crate::types::*;

fn assert_param_length(key: String, length: usize, expected_length: usize) -> Result<(), ASTError> {
    if length != expected_length {
        return Err(ASTError::ParamLengthError {
            key,
            length: length.to_string(),
            expected_length: expected_length.to_string(),
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
            _ => return Err(ASTError::ReturnTypeError {
                key: $key.to_string(),
                type_: ValueType::$value_type,
            }),
        }
    };
}

pub fn match_rule_with_account_chars<'a>(rules: &'a [SubAccountRule], account_chars: packed::AccountCharsReader) -> Result<Option<&'a SubAccountRule>, ASTError> {
    for (i, rule) in rules.iter().enumerate() {
        let value = handle_expression(format!("rules[{}].ast", i), &rule.ast, account_chars)?;
        let ret = assert_and_get_return!(
            format!("rules[{}]", i),
            value,
            Bool
        );

        if ret {
            return Ok(Some(rule));
        }
    }

    Ok(None)
}

fn handle_expression(key: String, ast: &Expression, account_chars: packed::AccountCharsReader) -> Result<Value, ASTError> {
    let value = match ast {
        Expression::Operator(operator) => handle_operator(key, operator, account_chars)?,
        Expression::Function(function) => handle_function(key, function, account_chars)?,
        Expression::Variable(variable) => handle_variable(key, variable, account_chars)?,
        Expression::Value(value) => value.value.clone(),
        // _ => todo!()
    };

    Ok(value)
}

fn handle_operator(key: String, operator: &OperatorExpression, account_chars: packed::AccountCharsReader) -> Result<Value, ASTError> {
    macro_rules! compare_values {
        ($method: ident) => {{
            assert_param_length(key.clone() + ".expressions", operator.expressions.len(), 2)?;

            let left = handle_expression(key.clone() + ".expressions[0]", &operator.expressions[0], account_chars)?;
            let right = handle_expression(key.clone() + ".expressions[1]", &operator.expressions[1], account_chars)?;

            assert_param_type_equal(key.clone() + ".expressions", &left, &right)?;
            left.$method(&right)
                .map_err(|err| ASTError::OperatorExecuteFailed { key, operator: operator.symbol.to_string(), reason: err.to_string() })?
        }};
    }

    let ret = match operator.symbol {
        SymbolType::And => {
            if operator.expressions.is_empty() {
                return Err(ASTError::ParamLengthError {
                    key,
                    length: "0".to_string(),
                    expected_length: "more than 0".to_string(),
                });
            }

            let mut ret = true;
            for (i, expression) in operator.expressions.iter().enumerate() {
                let value = handle_expression(format!("{}.expressions[{}]", key, i), expression, account_chars)?;
                match value {
                    Value::Bool(val) => {
                        if !val {
                            ret = false;
                        }
                    }
                    _ => return Err(ASTError::ReturnTypeError {
                        key: format!("{}.expressions[{}]", key, i),
                        type_: ValueType::Bool,
                    }),
                }
            }

            ret
        },
        SymbolType::Or => {
            if operator.expressions.is_empty() {
                return Err(ASTError::ParamLengthError {
                    key,
                    length: "0".to_string(),
                    expected_length: "more than 0".to_string(),
                });
            }

            let mut ret = false;
            for (i, expression) in operator.expressions.iter().enumerate() {
                let value = handle_expression(format!("{}.expressions[{}]", key, i), expression, account_chars)?;
                match value {
                    Value::Bool(val) => {
                        if val {
                            ret = true;
                        }
                    }
                    _ => return Err(ASTError::ReturnTypeError {
                        key: format!("{}.expressions[{}]", key, i),
                        type_: ValueType::Bool,
                    }),
                }
            }

            ret
        },
        SymbolType::Not => {
            assert_param_length(key.clone() + ".expressions", operator.expressions.len(), 1)?;

            let value = handle_expression(key.clone() + ".expressions[0]", &operator.expressions[0], account_chars)?;
            match value {
                Value::Bool(val) => !val,
                _ => return Err(ASTError::ReturnTypeError {
                    key: key.clone() + ".expressions[0]",
                    type_: ValueType::Bool,
                }),
            }
        },
        SymbolType::Equal => compare_values!(equal),
        SymbolType::Gt => compare_values!(greater_than),
        SymbolType::Gte => compare_values!(greater_than_or_equal),
        SymbolType::Lt => compare_values!(less_than),
        SymbolType::Lte => compare_values!(less_than_or_equal),
        // _ => todo!(),
    };

    Ok(Value::Bool(ret))
}

fn handle_function(key: String, function: &FunctionExpression, account_chars: packed::AccountCharsReader) -> Result<Value, ASTError> {
    let ret = match function.name {
        FnName::IncludeChars => {
            assert_param_length(key.clone() + ".arguments", function.arguments.len(), 2)?;

            let account_chars_str = handle_expression(key.clone() + ".arguments[0]", &function.arguments[0], account_chars)?;
            let chars = handle_expression(key.clone() + ".arguments[1]", &function.arguments[1], account_chars)?;

            include_chars(account_chars_str, chars)
                .map_err(|err| ASTError::FunctionExecuteFailed { key: key.clone(), name: function.name.to_string(), reason: err.to_string() })?
        },
        FnName::OnlyIncludeCharset => {
            assert_param_length(key.clone() + ".arguments", function.arguments.len(), 2)?;

            let charset = handle_expression(key.clone() + ".arguments[1]", &function.arguments[1], account_chars)?;

            only_include_charset(account_chars, charset)
                .map_err(|err| ASTError::FunctionExecuteFailed { key: key.clone(), name: function.name.to_string(), reason: err.to_string() })?
        },
        FnName::InList => {
            assert_param_length(key.clone() + ".arguments", function.arguments.len(), 2)?;

            let account = handle_expression(key.clone() + ".arguments[0]", &function.arguments[0], account_chars)?;
            let account_list = handle_expression(key.clone() + ".arguments[1]", &function.arguments[1], account_chars)?;

            in_list(account, account_list)
                .map_err(|err| ASTError::FunctionExecuteFailed { key: key.clone(), name: function.name.to_string(), reason: err.to_string() })?
        },
    };

    if ret.get_type() != ValueType::Bool {
        return Err(ASTError::ReturnTypeError {
            key,
            type_: ValueType::Bool,
        });
    }

    Ok(ret)
}

fn handle_variable(key: String, variable: &VariableExpression, account_chars: packed::AccountCharsReader) -> Result<Value, ASTError> {
    let ret = match variable.name {
        VarName::Account => {
            let account = String::from_utf8(account_chars.as_readable())
                .map_err(|_| ASTError::ParseUtf8StringFailed { key })?;
            Value::String(account)
        },
        VarName::AccountChars => {
            let mut string_vec = vec![];
            for (i, char) in account_chars.iter().enumerate() {
                let char = String::from_utf8(char.bytes().raw_data().to_owned())
                    .map_err(|_| ASTError::ParseUtf8StringFailed { key: format!("{}[{}]", key, i) })?;
                string_vec.push(char);
            }

            Value::StringVec(string_vec)
        },
        VarName::AccountLength => {
            Value::Uint32(account_chars.len() as u32)
        }
        // _ => todo!(),
    };

    Ok(ret)
}

fn include_chars(account_chars: Value, chars: Value) -> Result<Value, ASTError> {
    match (account_chars, chars) {
        (Value::StringVec(account_chars), Value::StringVec(chars)) => {
            for char in account_chars.iter() {
                if chars.contains(char) {
                    return  Ok(Value::Bool(true));
                }
            }

            Ok(Value::Bool(false))
        },
        _ => Err(ASTError::ValueTypeMismatch)
    }
}

fn only_include_charset(account_chars: packed::AccountCharsReader, charset: Value) -> Result<Value, ASTError> {
    let expected_charset = match charset {
        Value::CharsetType(charset) => charset,
        _ => return Err(ASTError::ValueTypeMismatch),
    };

    for item in account_chars.iter() {
        let charset_index = u32::from(item.char_set_name());
        let charset = CharSetType::try_from(charset_index)
            .map_err(|_| ASTError::UndefinedCharSetType { key: "".to_string(), type_: charset_index })?;

        if expected_charset != charset {
            return Ok(Value::Bool(false));
        }
    }

    Ok(Value::Bool(true))
}

fn in_list(account: Value, account_list: Value) -> Result<Value, ASTError> {
    match (account, account_list) {
        (Value::String(account), Value::StringVec(account_list)) => {
            Ok(Value::Bool(account_list.contains(&account)))
        },
        _ => Err(ASTError::ValueTypeMismatch)
    }
}