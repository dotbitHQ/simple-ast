#[cfg(feature = "no_std")]
use alloc::string::String;

#[cfg(feature = "no_std")]
use das_types::{constants::*, packed, prelude::*};
#[cfg(feature = "std")]
use das_types_std::{constants::*, packed, prelude::*};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

use crate::error::ASTError;

pub struct SubAccountRule {
    pub index: u32,
    pub name: String,
    pub note: String,
    pub price: u64,
    pub ast: Expression,
}

impl Into<packed::SubAccountRule> for SubAccountRule {
    fn into(self) -> packed::SubAccountRule {
        packed::SubAccountRuleBuilder::default()
            .index(packed::Uint32::from(self.index))
            .name(packed::Bytes::from(self.name.as_bytes()))
            .name(packed::Bytes::from(self.note.as_bytes()))
            .price(packed::Uint64::from(self.price))
            .ast(self.ast.into())
            .build()
    }
}

#[derive(Debug, Eq, PartialEq, IntoPrimitive, TryFromPrimitive, EnumString, Display)]
#[strum(serialize_all = "snake_case")]
#[repr(u8)]
pub enum ExpressionType {
    Operator,
    Function,
    Variable,
    Value,
}

impl Into<packed::Byte> for ExpressionType {
    fn into(self) -> packed::Byte {
        packed::Byte::new(self as u8)
    }
}

pub enum Expression {
    Operator(OperatorExpression),
    Function(FunctionExpression),
    Variable(VariableExpression),
    Value(ValueExpression),
}

impl Into<packed::ASTExpression> for Expression {
    fn into(self) -> packed::ASTExpression {
        let (type_, mol_bytes) = match self {
            Expression::Operator(expr) => {
                let mol: packed::ASTOperator = expr.into();
                (ExpressionType::Operator, mol.as_slice().to_vec())
            }
            Expression::Function(expr) => {
                let mol: packed::ASTFunction = expr.into();
                (ExpressionType::Function, mol.as_slice().to_vec())
            }
            Expression::Variable(expr) => {
                let mol: packed::ASTVariable = expr.into();
                (ExpressionType::Variable, mol.as_slice().to_vec())
            }
            Expression::Value(expr) => {
                let mol: packed::ASTValue = expr.into();
                (ExpressionType::Value, mol.as_slice().to_vec())
            }
        };

        packed::ASTExpressionBuilder::default()
            .expression_type(type_.into())
            .expression(packed::Bytes::from(mol_bytes))
            .build()
    }
}

#[derive(Debug, Eq, PartialEq, IntoPrimitive, TryFromPrimitive, EnumString, Display)]
#[repr(u8)]
pub enum SymbolType {
    #[strum(serialize = "not")]
    Not,
    #[strum(serialize = "and")]
    And,
    #[strum(serialize = "or")]
    Or,
    #[strum(serialize = ">")]
    Gt,
    #[strum(serialize = ">=")]
    Gte,
    #[strum(serialize = "<")]
    Lt,
    #[strum(serialize = "<=")]
    Lte,
    #[strum(serialize = "==")]
    Equal,
}

impl Into<packed::Byte> for SymbolType {
    fn into(self) -> packed::Byte {
        packed::Byte::new(self as u8)
    }
}

pub struct OperatorExpression {
    pub symbol: SymbolType,
    pub expressions: Vec<Expression>,
}

impl Into<packed::ASTOperator> for OperatorExpression {
    fn into(self) -> packed::ASTOperator {
        let expr_entities = packed::ASTExpressionsBuilder::default()
            .set(self.expressions.into_iter().map(Expression::into).collect())
            .build();

        packed::ASTOperatorBuilder::default()
            .symbol(self.symbol.into())
            .expressions(expr_entities)
            .build()
    }
}

#[derive(Debug, Eq, PartialEq, IntoPrimitive, TryFromPrimitive, EnumString, Display)]
#[strum(serialize_all = "snake_case")]
#[repr(u8)]
pub enum FnName {
    IncludeChars,
    OnlyIncludeCharset,
    InList,
}

impl Into<packed::Byte> for FnName {
    fn into(self) -> packed::Byte {
        packed::Byte::new(self as u8)
    }
}

pub struct FunctionExpression {
    pub name: FnName,
    pub arguments: Vec<Expression>,
}

impl Into<packed::ASTFunction> for FunctionExpression {
    fn into(self) -> packed::ASTFunction {
        let expr_entities = packed::ASTExpressionsBuilder::default()
            .set(self.arguments.into_iter().map(Expression::into).collect())
            .build();

        packed::ASTFunctionBuilder::default()
            .name(self.name.into())
            .arguments(expr_entities)
            .build()
    }
}

#[derive(Debug, Eq, PartialEq, IntoPrimitive, TryFromPrimitive, EnumString, Display)]
#[strum(serialize_all = "snake_case")]
#[repr(u8)]
pub enum VarName {
    Account,
    AccountChars,
    AccountLength,
}

impl Into<packed::Byte> for VarName {
    fn into(self) -> packed::Byte {
        packed::Byte::new(self as u8)
    }
}

pub struct VariableExpression {
    pub name: VarName,
}

impl Into<packed::ASTVariable> for VariableExpression {
    fn into(self) -> packed::ASTVariable {
        packed::ASTVariableBuilder::default().name(self.name.into()).build()
    }
}

#[derive(
    Debug, Copy, Clone, PartialEq, Serialize, Deserialize, IntoPrimitive, TryFromPrimitive, Display, EnumString,
)]
#[repr(u8)]
#[strum(serialize_all = "snake_case")]
pub enum ValueType {
    Bool,
    Uint8,
    Uint32,
    Uint64,
    Binary,
    #[strum(serialize = "binary[]")]
    BinaryVec,
    String,
    #[strum(serialize = "string[]")]
    StringVec,
    CharsetType,
}

impl Into<packed::Byte> for ValueType {
    fn into(self) -> packed::Byte {
        packed::Byte::new(self as u8)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValueExpression {
    pub value_type: ValueType,
    pub value: Value,
}

impl Into<packed::ASTValue> for ValueExpression {
    fn into(self) -> packed::ASTValue {
        packed::ASTValueBuilder::default()
            .value_type(self.value_type.into())
            .value(self.value.into())
            .build()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Value {
    Bool(bool),
    Uint8(u8),
    Uint32(u32),
    Uint64(u64),
    Binary(Vec<u8>),
    BinaryVec(Vec<Vec<u8>>),
    String(String),
    StringVec(Vec<String>),
    CharsetType(CharSetType),
}

impl Value {
    pub fn get_type(&self) -> ValueType {
        match self {
            Value::Bool(_) => ValueType::Bool,
            Value::Uint8(_) => ValueType::Uint8,
            Value::Uint32(_) => ValueType::Uint32,
            Value::Uint64(_) => ValueType::Uint64,
            Value::Binary(_) => ValueType::Binary,
            Value::BinaryVec(_) => ValueType::BinaryVec,
            Value::String(_) => ValueType::String,
            Value::StringVec(_) => ValueType::StringVec,
            Value::CharsetType(_) => ValueType::CharsetType,
        }
    }

    pub fn equal(&self, to: &Value) -> Result<bool, ASTError> {
        if self.get_type() != to.get_type() {
            return Err(ASTError::ValueTypeMismatch);
        }

        match (self, to) {
            (Value::Bool(val1), Value::Bool(val2)) => Ok(val1 == val2),
            (Value::Uint8(val1), Value::Uint8(val2)) => Ok(val1 == val2),
            (Value::Uint32(val1), Value::Uint32(val2)) => Ok(val1 == val2),
            (Value::Uint64(val1), Value::Uint64(val2)) => Ok(val1 == val2),
            (Value::Binary(val1), Value::Binary(val2)) => Ok(val1 == val2),
            (Value::BinaryVec(val1), Value::BinaryVec(val2)) => Ok(val1 == val2),
            (Value::String(val1), Value::String(val2)) => Ok(val1 == val2),
            (Value::StringVec(val1), Value::StringVec(val2)) => Ok(val1 == val2),
            (Value::CharsetType(val1), Value::CharsetType(val2)) => Ok(val1 == val2),
            _ => Err(ASTError::ValueOperatorUnsupported),
        }
    }

    pub fn greater_than(&self, to: &Value) -> Result<bool, ASTError> {
        if self.get_type() != to.get_type() {
            return Err(ASTError::ValueTypeMismatch);
        }

        match (self, to) {
            (Value::Uint8(val1), Value::Uint8(val2)) => Ok(val1 > val2),
            (Value::Uint32(val1), Value::Uint32(val2)) => Ok(val1 > val2),
            (Value::Uint64(val1), Value::Uint64(val2)) => Ok(val1 > val2),
            _ => Err(ASTError::ValueOperatorUnsupported),
        }
    }

    pub fn greater_than_or_equal(&self, to: &Value) -> Result<bool, ASTError> {
        if self.get_type() != to.get_type() {
            return Err(ASTError::ValueTypeMismatch);
        }

        match (self, to) {
            (Value::Uint8(val1), Value::Uint8(val2)) => Ok(val1 >= val2),
            (Value::Uint32(val1), Value::Uint32(val2)) => Ok(val1 >= val2),
            (Value::Uint64(val1), Value::Uint64(val2)) => Ok(val1 >= val2),
            _ => Err(ASTError::ValueOperatorUnsupported),
        }
    }

    pub fn less_than(&self, to: &Value) -> Result<bool, ASTError> {
        if self.get_type() != to.get_type() {
            return Err(ASTError::ValueTypeMismatch);
        }

        match (self, to) {
            (Value::Uint8(val1), Value::Uint8(val2)) => Ok(val1 < val2),
            (Value::Uint32(val1), Value::Uint32(val2)) => Ok(val1 < val2),
            (Value::Uint64(val1), Value::Uint64(val2)) => Ok(val1 < val2),
            _ => Err(ASTError::ValueOperatorUnsupported),
        }
    }

    pub fn less_than_or_equal(&self, to: &Value) -> Result<bool, ASTError> {
        if self.get_type() != to.get_type() {
            return Err(ASTError::ValueTypeMismatch);
        }

        match (self, to) {
            (Value::Uint8(val1), Value::Uint8(val2)) => Ok(val1 <= val2),
            (Value::Uint32(val1), Value::Uint32(val2)) => Ok(val1 <= val2),
            (Value::Uint64(val1), Value::Uint64(val2)) => Ok(val1 <= val2),
            _ => Err(ASTError::ValueOperatorUnsupported),
        }
    }
}

impl Into<packed::Bytes> for Value {
    fn into(self) -> packed::Bytes {
        match self {
            Value::Bool(val) => packed::Bytes::from(if val { vec![1] } else { vec![0] }),
            Value::Uint8(val) => packed::Bytes::from(val.to_le_bytes().as_slice()),
            Value::Uint32(val) => packed::Bytes::from(val.to_le_bytes().as_slice()),
            Value::Uint64(val) => packed::Bytes::from(val.to_le_bytes().as_slice()),
            Value::Binary(val) => packed::Bytes::from(val),
            Value::BinaryVec(val) => {
                let bytes_vec = val.into_iter().map(|item| packed::Bytes::from(item)).collect();
                let bytes_vec_entity = packed::BytesVecBuilder::default().set(bytes_vec).build();

                packed::Bytes::from(bytes_vec_entity.as_slice())
            }
            Value::String(val) => packed::Bytes::from(val.as_bytes()),
            Value::StringVec(val) => {
                let bytes_vec = val
                    .into_iter()
                    .map(|item| packed::Bytes::from(item.as_bytes()))
                    .collect();
                let bytes_vec_entity = packed::BytesVecBuilder::default().set(bytes_vec).build();

                packed::Bytes::from(bytes_vec_entity.as_slice())
            }
            Value::CharsetType(val) => packed::Bytes::from((val as u32).to_le_bytes().as_slice()),
        }
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;
    use crate::util;

    #[test]
    fn test_value_from_to_mol() {
        let expected_bytes = "120000000c0000000d000000000100000001";
        let expected_expr = ValueExpression {
            value_type: ValueType::Bool,
            value: Value::Bool(true),
        };

        let mol: packed::ASTValue = expected_expr.clone().into();
        assert_eq!(expected_bytes, hex::encode(mol.as_slice()));

        let mol = packed::ASTValue::from_slice(&hex::decode(expected_bytes).unwrap()).unwrap();
        let value = util::mol_reader_to_value(String::from("."), mol.as_reader()).unwrap();
        assert!(matches!(
            value,
            ValueExpression {
                value_type: ValueType::Bool,
                value: Value::Bool(true),
            }
        ));
    }

    #[test]
    fn test_variable_from_to_mol() {
        let expected_bytes = "090000000800000000";
        let expected_expr = VariableExpression { name: VarName::Account };

        let mol: packed::ASTVariable = expected_expr.into();
        assert_eq!(expected_bytes, hex::encode(mol.as_slice()));

        let mol = packed::ASTVariable::from_slice(&hex::decode(expected_bytes).unwrap()).unwrap();
        let value = util::mol_reader_to_variable(String::from("."), mol.as_reader()).unwrap();
        assert!(matches!(value, VariableExpression { name: VarName::Account }));
    }

    #[test]
    fn test_function_from_to_mol() {
        let expected_bytes = "590000000c0000000d000000014c0000000c000000260000001a0000000c0000000d0000000209000000090000000800000001260000000c0000000d0000000315000000150000000c0000000d000000080400000000000000";
        let expected_expr = FunctionExpression {
            name: FnName::OnlyIncludeCharset,
            arguments: vec![
                Expression::Variable(VariableExpression {
                    name: VarName::AccountChars,
                }),
                Expression::Value(ValueExpression {
                    value_type: ValueType::CharsetType,
                    value: Value::CharsetType(CharSetType::Emoji),
                }),
            ],
        };

        let mol: packed::ASTFunction = expected_expr.into();
        assert_eq!(expected_bytes, hex::encode(mol.as_slice()));

        let mol = packed::ASTFunction::from_slice(&hex::decode(expected_bytes).unwrap()).unwrap();
        let value = util::mol_reader_to_function(String::from("."), mol.as_reader()).unwrap();
        assert!(matches!(&value, FunctionExpression {
            name: FnName::OnlyIncludeCharset,
            arguments: args,
        } if args.len() == 2));
        assert!(matches!(
            &value.arguments[0],
            Expression::Variable(VariableExpression {
                name: VarName::AccountChars,
            })
        ));
        assert!(matches!(
            &value.arguments[1],
            Expression::Value(ValueExpression {
                value_type: ValueType::CharsetType,
                value: Value::CharsetType(CharSetType::Emoji),
            })
        ));
    }

    #[test]
    fn test_operator_from_to_mol() {
        let expected_bytes = "5f0000000c0000000d00000001520000000c0000002f000000230000000c0000000d0000000312000000120000000c0000000d000000000100000001230000000c0000000d0000000312000000120000000c0000000d000000000100000001";
        let expected_expr = OperatorExpression {
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
        };

        let mol: packed::ASTOperator = expected_expr.into();
        assert_eq!(expected_bytes, hex::encode(mol.as_slice()));

        let mol = packed::ASTOperator::from_slice(&hex::decode(expected_bytes).unwrap()).unwrap();
        let value = util::mol_reader_to_operator(String::from("."), mol.as_reader()).unwrap();
        assert!(matches!(&value, OperatorExpression {
            symbol: SymbolType::And,
            expressions: args,
        } if args.len() == 2));
        assert!(matches!(
            &value.expressions[0],
            Expression::Value(ValueExpression {
                value_type: ValueType::Bool,
                value: Value::Bool(true),
            })
        ));
        assert!(matches!(
            &value.expressions[1],
            Expression::Value(ValueExpression {
                value_type: ValueType::Bool,
                value: Value::Bool(true),
            })
        ));
    }

    #[test]
    fn test_value_from_json() {
        let expected_json = json!({
            "type": "value",
            "value_type": "uint8",
            "value": u8::MAX
        });
        let _expected_expr = ValueExpression {
            value_type: ValueType::Uint8,
            value: Value::Uint8(u8::MAX),
        };

        let value = util::json_to_value(String::new(), &expected_json).unwrap();
        assert!(matches!(
            value,
            ValueExpression {
                value_type: ValueType::Uint8,
                value: Value::Uint8(u8::MAX),
            }
        ));
    }

    #[test]
    fn test_variable_from_json() {
        let expected_json = json!({
            "type": "variable",
            "name": "account",
        });
        let _expected_expr = VariableExpression { name: VarName::Account };

        let value = util::json_to_variable(String::new(), &expected_json).unwrap();
        assert!(matches!(value, VariableExpression { name: VarName::Account }));
    }

    #[test]
    fn test_function_from_json() {
        let expected_json = json!({
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
                },
            ],
        });
        let _expected_expr = FunctionExpression {
            name: FnName::OnlyIncludeCharset,
            arguments: vec![
                Expression::Variable(VariableExpression {
                    name: VarName::AccountChars,
                }),
                Expression::Value(ValueExpression {
                    value_type: ValueType::CharsetType,
                    value: Value::CharsetType(CharSetType::Emoji),
                }),
            ],
        };

        let value = util::json_to_function(String::new(), &expected_json).unwrap();
        assert!(matches!(&value, FunctionExpression {
            name: FnName::OnlyIncludeCharset,
            arguments: args,
        } if args.len() == 2));
        assert!(matches!(
            &value.arguments[0],
            Expression::Variable(VariableExpression {
                name: VarName::AccountChars,
            })
        ));
        assert!(matches!(
            &value.arguments[1],
            Expression::Value(ValueExpression {
                value_type: ValueType::CharsetType,
                value: Value::CharsetType(CharSetType::Emoji),
            })
        ));
    }

    #[test]
    fn test_operator_from_json() {
        let expected_json = json!({
            "type": "operator",
            "symbol": "and",
            "expressions": [
                {
                    "type": "value",
                    "value_type": "bool",
                    "value": true,
                },
                {
                    "type": "value",
                    "value_type": "bool",
                    "value": true,
                },
            ],
        });
        let _expected_expr = OperatorExpression {
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
        };

        let value = util::json_to_operator(String::new(), &expected_json).unwrap();
        assert!(matches!(&value, OperatorExpression {
            symbol: SymbolType::And,
            expressions: args,
        } if args.len() == 2));
        assert!(matches!(
            &value.expressions[0],
            Expression::Value(ValueExpression {
                value_type: ValueType::Bool,
                value: Value::Bool(true),
            })
        ));
        assert!(matches!(
            &value.expressions[1],
            Expression::Value(ValueExpression {
                value_type: ValueType::Bool,
                value: Value::Bool(true),
            })
        ));
    }

    // #[test]
    // fn test_sub_account_rules_from_json() {
    //     let expected_json = json!([
    //         {
    //             "index": 0,
    //             "name": "Price of 1 Charactor Emoji DID",
    //             "note": "",
    //             "price": "",
    //             "ast": [
    //                 {
    //                     "type": "operator",
    //                     "symbol": "and",
    //                     "expressions": [
    //                         {
    //                             "type": "variable",
    //                             "name": "account_length",
    //                         },
    //                         {
    //                             "type": "value",
    //                             "value_type": "uint8",
    //                             "value": 1,
    //                         },
    //                     ],
    //                 },
    //                 {
    //                     "type": "function",
    //                     "name": "only_include_charset",
    //                     "arguments": [
    //                         {
    //                             "type": "variable",
    //                             "name": "account_chars",
    //                         },
    //                         {
    //                             "type": "value",
    //                             "value_type": "charset_type",
    //                             "value": "Emoji",
    //                         }
    //                     ],
    //                 }
    //             ]
    //         }
    //     ]);

    //     let _expected_expr =
    // }

    #[test]
    fn test_value_equal() {
        let val1 = Value::Uint8(u8::MAX);
        let val2 = Value::Uint8(u8::MAX);
        let val3 = Value::Uint8(u8::MIN);

        assert!(val1.equal(&val2).unwrap());
        assert!(!val1.equal(&val3).unwrap());
    }

    #[test]
    fn test_value_greater_than() {
        let val1 = Value::Uint8(100);
        let val2 = Value::Uint8(u8::MIN);
        let val3 = Value::Uint8(u8::MAX);

        assert!(val1.greater_than(&val2).unwrap());
        assert!(!val1.greater_than(&val3).unwrap());
    }

    #[test]
    fn test_value_greater_than_or_equal() {
        let val1 = Value::Uint8(100);
        let val2 = Value::Uint8(u8::MIN);
        let val3 = Value::Uint8(u8::MAX);

        assert!(val1.greater_than_or_equal(&val1).unwrap());
        assert!(val1.greater_than_or_equal(&val2).unwrap());
        assert!(!val1.greater_than_or_equal(&val3).unwrap());
    }

    #[test]
    fn test_value_less_than() {
        let val1 = Value::Uint8(100);
        let val2 = Value::Uint8(u8::MIN);
        let val3 = Value::Uint8(u8::MAX);

        assert!(val2.less_than(&val1).unwrap());
        assert!(!val3.less_than(&val1).unwrap());
    }

    #[test]
    fn test_value_less_than_or_equal() {
        let val1 = Value::Uint8(100);
        let val2 = Value::Uint8(u8::MIN);
        let val3 = Value::Uint8(u8::MAX);

        assert!(val1.less_than_or_equal(&val1).unwrap());
        assert!(val2.less_than_or_equal(&val1).unwrap());
        assert!(!val3.less_than_or_equal(&val1).unwrap());
    }
}
