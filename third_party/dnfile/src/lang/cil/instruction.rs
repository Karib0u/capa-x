use super::super::clr::{argument::Argument, local::Local, token::Token};
use super::enums::*;
use crate::{Result, error::Error};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub enum Operand {
    Token(Token),
    StringToken(Token),
    Local(Local),
    Argument(Argument),
    Arguments(Vec<Operand>),
    Int(i64),
    Float(f64),
    None,
}

impl Operand {
    pub fn value(&self) -> Result<usize> {
        match self {
            Self::Token(t) => Ok(t.value),
            Self::StringToken(t) => Ok(t.value),
            Self::Argument(_)
            | Self::Local(_)
            | Self::Arguments(_)
            | Self::Int(_)
            | Self::Float(_)
            | Self::None => Err(Error::OperandHasNoValue),
        }
    }
}

impl TryInto<f64> for Operand {
    type Error = crate::error::Error;
    fn try_into(self) -> std::result::Result<f64, Self::Error> {
        match self {
            Self::StringToken(_)
            | Self::Token(_)
            | Self::Local(_)
            | Self::Argument(_)
            | Self::Arguments(_)
            | Self::None => Err(Error::ConversionError("to f64")),
            Self::Int(i) => Ok(i as f64),
            Self::Float(f) => Ok(f),
        }
    }
}

impl TryInto<Argument> for Operand {
    type Error = crate::error::Error;
    fn try_into(self) -> std::result::Result<Argument, Self::Error> {
        match self {
            Self::StringToken(_)
            | Self::Token(_)
            | Self::Local(_)
            | Self::Int(_)
            | Self::Float(_)
            | Self::Arguments(_)
            | Self::None => Err(Error::ConversionError("to argument")),
            Self::Argument(a) => Ok(a),
        }
    }
}

impl TryInto<Local> for Operand {
    type Error = crate::error::Error;
    fn try_into(self) -> std::result::Result<Local, Self::Error> {
        match self {
            Self::StringToken(_)
            | Self::Token(_)
            | Self::Argument(_)
            | Self::Int(_)
            | Self::Float(_)
            | Self::Arguments(_)
            | Self::None => Err(Error::ConversionError("to local")),
            Self::Local(a) => Ok(a),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Instruction {
    pub offset: usize,
    pub opcode: super::opcode::OpCode,
    pub opcode_bytes: Vec<u8>,
    pub operand: Operand,
    pub operand_bytes: Vec<u8>,
}

impl Default for Instruction {
    fn default() -> Self {
        Self::new()
    }
}

impl Instruction {
    pub fn new() -> Self {
        Self {
            offset: 0,
            opcode: super::opcode::OpCode::new(
                "UNKNOWN1",
                OpCodeValue::UNKNOWN1,
                OperandType::InlineNone,
                FlowControl::Meta,
                OpCodeType::Nternal,
                StackBehaviour::Push0,
                StackBehaviour::Pop0,
            ),
            opcode_bytes: vec![],
            operand: Operand::None,
            operand_bytes: vec![],
        }
    }

    pub fn size(&self) -> usize {
        let opcode = &self.opcode;
        if [
            OperandType::InlineBrTarget,
            OperandType::InlineField,
            OperandType::InlineI,
            OperandType::InlineMethod,
            OperandType::InlineSig,
            OperandType::InlineString,
            OperandType::InlineTok,
            OperandType::InlineType,
            OperandType::ShortInlineR,
        ]
        .contains(&opcode.operand_type)
        {
            opcode.size() + 4
        } else if [OperandType::InlineI8, OperandType::InlineR].contains(&opcode.operand_type) {
            opcode.size() + 8
        } else if [OperandType::InlineSwitch].contains(&opcode.operand_type) {
            if let Operand::Arguments(v) = &self.operand {
                opcode.size() + 4 + v.len() * 4
            } else {
                opcode.size() + 4
            }
        } else if [OperandType::InlineVar].contains(&opcode.operand_type) {
            opcode.size() + 2
        } else if [
            OperandType::ShortInlineBrTarget,
            OperandType::ShortInlineI,
            OperandType::ShortInlineVar,
        ]
        .contains(&opcode.operand_type)
        {
            opcode.size() + 1
        // } else if vec![OperandType::InlineNone, OperandType::InlinePhi]
        //     .contains(&opcode.operand_type)
        // {
        //     opcode.size()
        } else {
            opcode.size()
        }
    }

    pub fn is_leave(&self) -> bool {
        [OpCodeValue::Leave, OpCodeValue::Leave_S].contains(&self.opcode.value)
    }

    pub fn is_br(&self) -> bool {
        [OpCodeValue::Br, OpCodeValue::Br_S].contains(&self.opcode.value)
    }

    pub fn is_br_false(&self) -> bool {
        [OpCodeValue::Brfalse, OpCodeValue::Brfalse_S].contains(&self.opcode.value)
    }

    pub fn is_br_true(&self) -> bool {
        [OpCodeValue::Brtrue, OpCodeValue::Brtrue_S].contains(&self.opcode.value)
    }

    pub fn is_cond_br(&self) -> bool {
        [
            OpCodeValue::Bge,
            OpCodeValue::Bge_S,
            OpCodeValue::Bge_Un,
            OpCodeValue::Bge_Un_S,
            OpCodeValue::Blt,
            OpCodeValue::Blt_S,
            OpCodeValue::Blt_Un,
            OpCodeValue::Blt_Un_S,
            OpCodeValue::Bgt,
            OpCodeValue::Bgt_S,
            OpCodeValue::Bgt_Un,
            OpCodeValue::Bgt_Un_S,
            OpCodeValue::Ble,
            OpCodeValue::Ble_S,
            OpCodeValue::Ble_Un,
            OpCodeValue::Ble_Un_S,
            OpCodeValue::Brfalse,
            OpCodeValue::Brfalse_S,
            OpCodeValue::Brtrue,
            OpCodeValue::Brtrue_S,
            OpCodeValue::Beq,
            OpCodeValue::Beq_S,
            OpCodeValue::Bne_Un,
            OpCodeValue::Bne_Un_S,
        ]
        .contains(&self.opcode.value)
    }

    pub fn is_ldstr(&self) -> bool {
        [OpCodeValue::Ldstr].contains(&self.opcode.value)
    }

    pub fn is_ldc(&self) -> bool {
        [
            OpCodeValue::Ldc_I4_M1,
            OpCodeValue::Ldc_I4_0,
            OpCodeValue::Ldc_I4_1,
            OpCodeValue::Ldc_I4_2,
            OpCodeValue::Ldc_I4_3,
            OpCodeValue::Ldc_I4_4,
            OpCodeValue::Ldc_I4_5,
            OpCodeValue::Ldc_I4_6,
            OpCodeValue::Ldc_I4_7,
            OpCodeValue::Ldc_I4_8,
            OpCodeValue::Ldc_I4_S,
            OpCodeValue::Ldc_I4,
            OpCodeValue::Ldc_I8,
            OpCodeValue::Ldc_R4,
            OpCodeValue::Ldc_R8,
        ]
        .contains(&self.opcode.value)
    }

    pub fn get_ldc(&self) -> Option<f64> {
        let s = self.operand.clone().try_into().ok();
        match self.opcode.value {
            OpCodeValue::Ldc_I4_M1 => Some(-1.0),
            OpCodeValue::Ldc_I4_0 => Some(0.0),
            OpCodeValue::Ldc_I4_1 => Some(1.0),
            OpCodeValue::Ldc_I4_2 => Some(2.0),
            OpCodeValue::Ldc_I4_3 => Some(3.0),
            OpCodeValue::Ldc_I4_4 => Some(4.0),
            OpCodeValue::Ldc_I4_5 => Some(5.0),
            OpCodeValue::Ldc_I4_6 => Some(6.0),
            OpCodeValue::Ldc_I4_7 => Some(7.0),
            OpCodeValue::Ldc_I4_8 => Some(8.0),
            OpCodeValue::Ldc_I4_S => s,
            OpCodeValue::Ldc_I4 => s,
            OpCodeValue::Ldc_I8 => s,
            OpCodeValue::Ldc_R4 => s,
            OpCodeValue::Ldc_R8 => s,
            _ => None,
        }
    }

    pub fn is_ldarg(&self) -> bool {
        [
            OpCodeValue::Ldarg,
            OpCodeValue::Ldarg_0,
            OpCodeValue::Ldarg_1,
            OpCodeValue::Ldarg_2,
            OpCodeValue::Ldarg_3,
            OpCodeValue::Ldarg_S,
            OpCodeValue::Ldarga,
            OpCodeValue::Ldarga_S,
        ]
        .contains(&self.opcode.value)
    }

    pub fn get_ldarg(&self) -> Option<Argument> {
        let s = self.operand.clone().try_into().ok();
        match &self.opcode.value {
            OpCodeValue::Ldarg
            | OpCodeValue::Ldarga
            | OpCodeValue::Ldarg_S
            | OpCodeValue::Ldarga_S => s,
            OpCodeValue::Ldarg_0 => Some(Argument::new(0)),
            OpCodeValue::Ldarg_1 => Some(Argument::new(1)),
            OpCodeValue::Ldarg_2 => Some(Argument::new(2)),
            OpCodeValue::Ldarg_3 => Some(Argument::new(3)),
            _ => None,
        }
    }

    pub fn is_starg(&self) -> bool {
        [OpCodeValue::Starg, OpCodeValue::Starg_S].contains(&self.opcode.value)
    }

    pub fn get_starg(&self) -> Option<Argument> {
        let s = self.operand.clone().try_into().ok();
        if [OpCodeValue::Starg, OpCodeValue::Starg_S].contains(&self.opcode.value) {
            s
        } else {
            None
        }
    }

    pub fn is_ldloc(&self) -> bool {
        [
            OpCodeValue::Ldloc,
            OpCodeValue::Ldloc_0,
            OpCodeValue::Ldloc_1,
            OpCodeValue::Ldloc_2,
            OpCodeValue::Ldloc_3,
            OpCodeValue::Ldloc_S,
            OpCodeValue::Ldloca,
            OpCodeValue::Ldloca_S,
        ]
        .contains(&self.opcode.value)
    }

    pub fn get_ldoc(&self) -> Option<Local> {
        let s = self.operand.clone().try_into().ok();
        match self.opcode.value {
            OpCodeValue::Ldloc
            | OpCodeValue::Ldloc_S
            | OpCodeValue::Ldloca
            | OpCodeValue::Ldloca_S => s,
            OpCodeValue::Ldloc_0 => Some(Local::new(0)),
            OpCodeValue::Ldloc_1 => Some(Local::new(1)),
            OpCodeValue::Ldloc_2 => Some(Local::new(2)),
            OpCodeValue::Ldloc_3 => Some(Local::new(3)),
            _ => None,
        }
    }

    pub fn is_stloc(&self) -> bool {
        [
            OpCodeValue::Stloc,
            OpCodeValue::Stloc_0,
            OpCodeValue::Stloc_1,
            OpCodeValue::Stloc_2,
            OpCodeValue::Stloc_3,
            OpCodeValue::Stloc_S,
        ]
        .contains(&self.opcode.value)
    }

    pub fn get_stloc(&self) -> Option<Local> {
        let s = self.operand.clone().try_into().ok();
        match self.opcode.value {
            OpCodeValue::Stloc | OpCodeValue::Stloc_S => s,
            OpCodeValue::Stloc_0 => Some(Local::new(0)),
            OpCodeValue::Stloc_1 => Some(Local::new(1)),
            OpCodeValue::Stloc_2 => Some(Local::new(2)),
            OpCodeValue::Stloc_3 => Some(Local::new(3)),
            _ => None,
        }
    }
}
