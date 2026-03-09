use crate::{flags, Connection, DataUpdateResult, Error as ValueError, IrsdkHeader, VarType, HWND_BROADCAST};
use encoding::all::WINDOWS_1252;
use encoding::{DecoderTrap, Encoding};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::mem::size_of;
use std::rc::Rc;
use std::slice;
use std::time::{Duration, Instant};
use std::{thread, usize};
use windows::Win32::Foundation::{GetLastError, LPARAM, WIN32_ERROR, WPARAM};
use windows::Win32::System::Memory;
use windows::Win32::UI::WindowsAndMessaging::SendNotifyMessageA;

const MAX_SAFE_VARS: usize = 16_384;
const IRSDK_MAX_STRING: usize = 32;
const IRSDK_MAX_DESC: usize = 64;

#[repr(C)]
#[derive(Clone, Copy)]
struct RawVarHeader {
    var_type: i32,
    offset: i32,
    count: i32,
    count_as_time: u8,
    pad: [i8; 3],
    name: [u8; IRSDK_MAX_STRING],
    desc: [u8; IRSDK_MAX_DESC],
    unit: [u8; IRSDK_MAX_STRING],
}

#[derive(Debug)]
pub enum SafeError {
    Win32(WIN32_ERROR),
    MappingLayout(&'static str),
    Range(&'static str),
    InvalidVar(&'static str),
    InvalidBool(u8),
    Utf8(std::str::Utf8Error),
    Type(ValueError),
    VarNotFound(String),
}

impl From<WIN32_ERROR> for SafeError {
    fn from(value: WIN32_ERROR) -> Self {
        Self::Win32(value)
    }
}

impl From<ValueError> for SafeError {
    fn from(value: ValueError) -> Self {
        Self::Type(value)
    }
}

#[derive(Debug, Clone)]
pub struct SafeVar {
    session_id: i32,
    var_type: VarType,
    offset: usize,
    count: usize,
    count_as_time: u8,
    name: String,
    desc: String,
    unit: String,
}

impl SafeVar {
    pub fn var_type(&self) -> VarType {
        self.var_type
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn desc(&self) -> &str {
        &self.desc
    }

    pub fn unit(&self) -> &str {
        &self.unit
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub fn count_as_time(&self) -> bool {
        self.count_as_time != 0
    }

    fn size(&self) -> Result<usize, SafeError> {
        elem_size(self.var_type)
            .checked_mul(self.count)
            .ok_or(SafeError::Range("var size overflow"))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum SafeValue {
    Char(u8),
    Chars(Vec<u8>),
    Bool(bool),
    Bools(Vec<bool>),
    Int(i32),
    Ints(Vec<i32>),
    Bitfield(i32),
    Bitfields(Vec<i32>),
    Float(f32),
    Floats(Vec<f32>),
    Double(f64),
    Doubles(Vec<f64>),
}

impl SafeValue {
    pub fn as_f64(&self) -> Result<f64, SafeError> {
        match self {
            SafeValue::Double(v) => Ok(*v),
            _ => Err(SafeError::Type(ValueError::InvalidType)),
        }
    }

    pub fn as_f32(&self) -> Result<f32, SafeError> {
        match self {
            SafeValue::Float(v) => Ok(*v),
            _ => Err(SafeError::Type(ValueError::InvalidType)),
        }
    }

    pub fn as_i32(&self) -> Result<i32, SafeError> {
        match self {
            SafeValue::Int(v) => Ok(*v),
            SafeValue::Bitfield(v) => Ok(*v),
            _ => Err(SafeError::Type(ValueError::InvalidType)),
        }
    }

    pub fn as_bool(&self) -> Result<bool, SafeError> {
        match self {
            SafeValue::Bool(v) => Ok(*v),
            _ => Err(SafeError::Type(ValueError::InvalidType)),
        }
    }

    pub fn as_u8(&self) -> Result<u8, SafeError> {
        match self {
            SafeValue::Char(v) => Ok(*v),
            _ => Err(SafeError::Type(ValueError::InvalidType)),
        }
    }
}

#[derive(Debug)]
pub struct Client {
    conn: Option<Rc<Connection>>,
    session_id: i32,
}

impl Client {
    pub fn new() -> Self {
        Self {
            conn: None,
            session_id: 0,
        }
    }

    pub fn session(&mut self) -> Result<Option<Session>, SafeError> {
        self.ensure_connection()?;
        let Some(conn) = &self.conn else {
            return Ok(None);
        };
        if !conn_is_connected(conn)? {
            return Ok(None);
        }

        let sid = self.session_id;
        self.session_id += 1;
        let (vars, vars_by_name) = load_var_cache(conn, sid)?;
        let mut s = Session {
            session_id: sid,
            conn: conn.clone(),
            last_tick_count: -2,
            data: bytes::BytesMut::new(),
            expired: false,
            vars,
            vars_by_name,
        };
        match s.wait_for_data(Duration::from_millis(16))? {
            DataUpdateResult::Updated => Ok(Some(s)),
            _ => Ok(None),
        }
    }

    pub fn wait_for_session(&mut self, wait: Duration) -> Result<Option<Session>, SafeError> {
        match &self.conn {
            Some(c) => {
                unsafe { c.wait_for_new_data(wait) };
                self.session()
            }
            None => {
                let start = Instant::now();
                let loop_wait = Duration::from_millis(1000);
                loop {
                    let r = self.session()?;
                    if r.is_some() || start.elapsed() > wait {
                        return Ok(r);
                    }
                    thread::sleep(loop_wait);
                }
            }
        }
    }

    fn ensure_connection(&mut self) -> Result<(), SafeError> {
        if self.conn.is_none() {
            let conn = unsafe { Connection::new() }.map_err(SafeError::Win32)?;
            self.conn = Some(Rc::new(conn));
        }
        Ok(())
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct Session {
    session_id: i32,
    conn: Rc<Connection>,
    last_tick_count: i32,
    data: bytes::BytesMut,
    expired: bool,
    vars: Vec<SafeVar>,
    vars_by_name: HashMap<String, usize>,
}

impl Session {
    pub fn connected(&self) -> Result<bool, SafeError> {
        Ok(!self.expired()?)
    }

    pub fn expired(&self) -> Result<bool, SafeError> {
        Ok(self.expired || !conn_is_connected(&self.conn)?)
    }

    pub fn wait_for_data(&mut self, wait: Duration) -> Result<DataUpdateResult, SafeError> {
        let r = self.get_new_data()?;
        if r == DataUpdateResult::NoUpdate {
            unsafe { self.conn.wait_for_new_data(wait) };
            self.get_new_data()
        } else {
            Ok(r)
        }
    }

    pub fn get_new_data(&mut self) -> Result<DataUpdateResult, SafeError> {
        if self.expired()? {
            self.expired = true;
            return Ok(DataUpdateResult::SessionExpired);
        }

        let (tick_count, row) = latest_row_copy(&self.conn)?;
        match tick_count.cmp(&self.last_tick_count) {
            Ordering::Greater => {
                self.data.clear();
                self.data.extend_from_slice(&row);
                self.last_tick_count = tick_count;
                Ok(DataUpdateResult::Updated)
            }
            Ordering::Less => {
                self.expired = true;
                Ok(DataUpdateResult::SessionExpired)
            }
            Ordering::Equal => Ok(DataUpdateResult::NoUpdate),
        }
    }

    pub fn dump_vars(&self) -> Result<(), SafeError> {
        for var in self.vars() {
            let value = self.var_value(&var)?;
            println!(
                "{:40} {:32}: {:?}: {}: {}: {:?}",
                var.desc(),
                var.name(),
                var.var_type(),
                var.count(),
                var.count_as_time(),
                value,
            );
        }
        Ok(())
    }

    pub fn vars(&self) -> &[SafeVar] {
        &self.vars
    }

    pub fn find_var(&self, name: &str) -> Result<Option<SafeVar>, SafeError> {
        Ok(self
            .vars_by_name
            .get(name)
            .and_then(|idx| self.vars.get(*idx))
            .cloned())
    }

    pub fn require_var(&self, name: &str) -> Result<SafeVar, SafeError> {
        self.find_var(name)?
            .ok_or_else(|| SafeError::VarNotFound(name.to_string()))
    }

    pub fn get<T>(&self, name: &str) -> Result<T, SafeError>
    where
        T: TryFrom<SafeValue, Error = SafeError>,
    {
        let var = self.require_var(name)?;
        self.value(&var)
    }

    pub fn get_opt<T>(&self, name: &str) -> Result<Option<T>, SafeError>
    where
        T: TryFrom<SafeValue, Error = SafeError>,
    {
        let Some(var) = self.find_var(name)? else {
            return Ok(None);
        };
        Ok(Some(self.value(&var)?))
    }

    pub fn for_each_update<F>(&mut self, wait: Duration, mut f: F) -> Result<(), SafeError>
    where
        F: FnMut(&Session) -> Result<(), SafeError>,
    {
        loop {
            match self.wait_for_data(wait)? {
                DataUpdateResult::Updated => f(self)?,
                DataUpdateResult::NoUpdate => {}
                DataUpdateResult::FailedToCopyRow => {}
                DataUpdateResult::SessionExpired => return Ok(()),
            }
        }
    }

    pub fn var_value(&self, var: &SafeVar) -> Result<SafeValue, SafeError> {
        if var.session_id != self.session_id {
            return Err(SafeError::InvalidVar(
                "Var was issued by a different Session",
            ));
        }

        let value_size = var.size()?;
        let end = var
            .offset
            .checked_add(value_size)
            .ok_or(SafeError::Range("var offset overflow"))?;
        if end > self.data.len() {
            return Err(SafeError::Range("var range outside row buffer"));
        }

        let bytes = &self.data[var.offset..end];
        decode_value(var.var_type, var.count, bytes)
    }

    pub fn value<T>(&self, var: &SafeVar) -> Result<T, SafeError>
    where
        T: TryFrom<SafeValue, Error = SafeError>,
    {
        let v = self.var_value(var)?;
        v.try_into()
    }

    pub fn session_info_update(&self) -> Result<i32, SafeError> {
        Ok(header_copy(&self.conn)?.session_info_update)
    }

    pub fn session_info(&self) -> Result<String, SafeError> {
        let hdr = header_copy(&self.conn)?;
        let (base, len) = mapping_region(&self.conn)?;

        let offset = i32_to_usize(hdr.session_info_offset, "negative session_info_offset")?;
        let total = i32_to_usize(hdr.session_info_len, "negative session_info_len")?;
        let bytes = checked_region_slice(base, len, offset, total)?;

        let null_pos = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
        let yaml = &bytes[..null_pos];
        WINDOWS_1252
            .decode(yaml, DecoderTrap::Replace)
            .map_err(|_| SafeError::MappingLayout("failed to decode session_info"))
    }

    pub fn broadcast_msg(&self, msg: flags::BroadcastMsg) -> Result<(), SafeError> {
        let (cmd_msg_id, (var1, var2)) = msg.params();
        let x = make_long(cmd_msg_id, var1);
        let r = unsafe {
            SendNotifyMessageA(
                HWND_BROADCAST,
                self.conn.broadcast_msg_id,
                WPARAM(x as usize),
                LPARAM(var2),
            )
        };
        if r.as_bool() {
            Ok(())
        } else {
            Err(SafeError::Win32(unsafe { GetLastError() }))
        }
    }
}

fn make_long(var1: i16, var2: i16) -> isize {
    let x = ((var1 as u32) & 0xFFFF) | (((var2 as u32) & 0xFFFF) << 16);
    x as isize
}

fn decode_var_header(session_id: i32, h: RawVarHeader) -> Result<SafeVar, SafeError> {
    let var_type = decode_var_type(h.var_type)?;
    let offset = i32_to_usize(h.offset, "negative var offset")?;
    let count = i32_to_usize(h.count, "negative var count")?;
    if count == 0 {
        return Err(SafeError::InvalidVar("var count cannot be zero"));
    }

    Ok(SafeVar {
        session_id,
        var_type,
        offset,
        count,
        count_as_time: h.count_as_time,
        name: fixed_cstr(&h.name)?,
        desc: fixed_cstr(&h.desc)?,
        unit: fixed_cstr(&h.unit)?,
    })
}

fn decode_var_type(raw: i32) -> Result<VarType, SafeError> {
    match raw {
        0 => Ok(VarType::Char),
        1 => Ok(VarType::Bool),
        2 => Ok(VarType::Int),
        3 => Ok(VarType::Bitfield),
        4 => Ok(VarType::Float),
        5 => Ok(VarType::Double),
        _ => Err(SafeError::InvalidVar("unknown var_type value")),
    }
}

fn elem_size(var_type: VarType) -> usize {
    match var_type {
        VarType::Char => 1,
        VarType::Bool => 1,
        VarType::Int => 4,
        VarType::Bitfield => 4,
        VarType::Float => 4,
        VarType::Double => 8,
        _ => 0,
    }
}

fn decode_value(var_type: VarType, count: usize, bytes: &[u8]) -> Result<SafeValue, SafeError> {
    if count == 1 {
        return decode_scalar(var_type, bytes);
    }

    match var_type {
        VarType::Char => Ok(SafeValue::Chars(bytes.to_vec())),
        VarType::Bool => {
            let mut out = Vec::with_capacity(count);
            for b in bytes {
                match *b {
                    0 => out.push(false),
                    1 => out.push(true),
                    x => return Err(SafeError::InvalidBool(x)),
                }
            }
            Ok(SafeValue::Bools(out))
        }
        VarType::Int => {
            let mut out = Vec::with_capacity(count);
            for chunk in bytes.chunks_exact(4) {
                let mut arr = [0u8; 4];
                arr.copy_from_slice(chunk);
                out.push(i32::from_le_bytes(arr));
            }
            Ok(SafeValue::Ints(out))
        }
        VarType::Bitfield => {
            let mut out = Vec::with_capacity(count);
            for chunk in bytes.chunks_exact(4) {
                let mut arr = [0u8; 4];
                arr.copy_from_slice(chunk);
                out.push(i32::from_le_bytes(arr));
            }
            Ok(SafeValue::Bitfields(out))
        }
        VarType::Float => {
            let mut out = Vec::with_capacity(count);
            for chunk in bytes.chunks_exact(4) {
                let mut arr = [0u8; 4];
                arr.copy_from_slice(chunk);
                out.push(f32::from_le_bytes(arr));
            }
            Ok(SafeValue::Floats(out))
        }
        VarType::Double => {
            let mut out = Vec::with_capacity(count);
            for chunk in bytes.chunks_exact(8) {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(chunk);
                out.push(f64::from_le_bytes(arr));
            }
            Ok(SafeValue::Doubles(out))
        }
        _ => Err(SafeError::InvalidVar("unsupported var type")),
    }
}

fn decode_scalar(var_type: VarType, bytes: &[u8]) -> Result<SafeValue, SafeError> {
    match var_type {
        VarType::Char => Ok(SafeValue::Char(bytes[0])),
        VarType::Bool => match bytes[0] {
            0 => Ok(SafeValue::Bool(false)),
            1 => Ok(SafeValue::Bool(true)),
            x => Err(SafeError::InvalidBool(x)),
        },
        VarType::Int => {
            let mut arr = [0u8; 4];
            arr.copy_from_slice(&bytes[..4]);
            Ok(SafeValue::Int(i32::from_le_bytes(arr)))
        }
        VarType::Bitfield => {
            let mut arr = [0u8; 4];
            arr.copy_from_slice(&bytes[..4]);
            Ok(SafeValue::Bitfield(i32::from_le_bytes(arr)))
        }
        VarType::Float => {
            let mut arr = [0u8; 4];
            arr.copy_from_slice(&bytes[..4]);
            Ok(SafeValue::Float(f32::from_le_bytes(arr)))
        }
        VarType::Double => {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&bytes[..8]);
            Ok(SafeValue::Double(f64::from_le_bytes(arr)))
        }
        _ => Err(SafeError::InvalidVar("unsupported var type")),
    }
}

fn load_var_cache(
    conn: &Connection,
    session_id: i32,
) -> Result<(Vec<SafeVar>, HashMap<String, usize>), SafeError> {
    let raw = variables_copy(conn)?;
    let mut vars = Vec::with_capacity(raw.len());
    for h in raw {
        vars.push(decode_var_header(session_id, h)?);
    }
    let mut vars_by_name = HashMap::with_capacity(vars.len());
    for (i, v) in vars.iter().enumerate() {
        vars_by_name.insert(v.name().to_string(), i);
    }
    Ok((vars, vars_by_name))
}

fn conn_is_connected(conn: &Connection) -> Result<bool, SafeError> {
    Ok(header_copy(conn)?
        .status
        .intersects(flags::StatusField::CONNECTED))
}

fn latest_row_copy(conn: &Connection) -> Result<(i32, Vec<u8>), SafeError> {
    let hdr = header_copy(conn)?;
    let (base, len) = mapping_region(conn)?;

    let num_buf = i32_to_usize(hdr.num_buf, "negative num_buf")?;
    if num_buf == 0 || num_buf > crate::IRSDK_MAX_BUFS {
        return Err(SafeError::MappingLayout("invalid num_buf"));
    }

    let mut latest = &hdr.var_buf[0];
    for i in 1..num_buf {
        let candidate = &hdr.var_buf[i];
        if candidate.tick_count > latest.tick_count {
            latest = candidate;
        }
    }

    let buf_len = i32_to_usize(hdr.buf_len, "negative buf_len")?;
    let buf_offset = i32_to_usize(latest.buf_offset, "negative buf_offset")?;
    let row = checked_region_slice(base, len, buf_offset, buf_len)?.to_vec();

    Ok((latest.tick_count, row))
}

fn variables_copy(conn: &Connection) -> Result<Vec<RawVarHeader>, SafeError> {
    let hdr = header_copy(conn)?;
    let (base, len) = mapping_region(conn)?;

    let num_vars = i32_to_usize(hdr.num_vars, "negative num_vars")?;
    if num_vars > MAX_SAFE_VARS {
        return Err(SafeError::MappingLayout("num_vars too large"));
    }

    let offset = i32_to_usize(hdr.var_header_offset, "negative var_header_offset")?;
    let bytes_len = num_vars
        .checked_mul(size_of::<RawVarHeader>())
        .ok_or(SafeError::Range("var headers size overflow"))?;
    let bytes = checked_region_slice(base, len, offset, bytes_len)?;

    let mut vars = Vec::with_capacity(num_vars);
    for i in 0..num_vars {
        let start = i
            .checked_mul(size_of::<RawVarHeader>())
            .ok_or(SafeError::Range("var header index overflow"))?;
        let p = unsafe { bytes.as_ptr().add(start) as *const RawVarHeader };
        let h = unsafe { std::ptr::read_unaligned(p) };
        vars.push(h);
    }
    Ok(vars)
}

fn header_copy(conn: &Connection) -> Result<IrsdkHeader, SafeError> {
    let (base, len) = mapping_region(conn)?;
    let bytes = checked_region_slice(base, len, 0, size_of::<IrsdkHeader>())?;
    let p = bytes.as_ptr() as *const IrsdkHeader;
    Ok(unsafe { std::ptr::read_unaligned(p) })
}

fn mapping_region(conn: &Connection) -> Result<(*const u8, usize), SafeError> {
    let mut mbi = Memory::MEMORY_BASIC_INFORMATION::default();
    let queried = unsafe {
        Memory::VirtualQuery(
            conn.shared_mem as *const core::ffi::c_void,
            &mut mbi,
            size_of::<Memory::MEMORY_BASIC_INFORMATION>(),
        )
    };
    if queried == 0 {
        return Err(SafeError::Win32(unsafe { GetLastError() }));
    }

    let base = mbi.BaseAddress as usize;
    let region_size = mbi.RegionSize;
    if region_size == 0 {
        return Err(SafeError::MappingLayout("virtual query returned empty region"));
    }

    let ptr = conn.shared_mem as usize;
    let region_end = base
        .checked_add(region_size)
        .ok_or(SafeError::Range("region size overflow"))?;
    if ptr < base || ptr >= region_end {
        return Err(SafeError::MappingLayout(
            "shared_mem pointer outside mapped region",
        ));
    }

    Ok((conn.shared_mem as *const u8, region_end - ptr))
}

fn checked_region_slice<'a>(
    base: *const u8,
    len: usize,
    offset: usize,
    bytes: usize,
) -> Result<&'a [u8], SafeError> {
    let end = offset
        .checked_add(bytes)
        .ok_or(SafeError::Range("slice end overflow"))?;
    if end > len {
        return Err(SafeError::Range("slice outside mapped region"));
    }

    let start_ptr = unsafe { base.add(offset) };
    Ok(unsafe { slice::from_raw_parts(start_ptr, bytes) })
}

fn i32_to_usize(v: i32, msg: &'static str) -> Result<usize, SafeError> {
    usize::try_from(v).map_err(|_| SafeError::Range(msg))
}

fn fixed_cstr<const N: usize>(bytes: &[u8; N]) -> Result<String, SafeError> {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(N);
    let s = std::str::from_utf8(&bytes[..end]).map_err(SafeError::Utf8)?;
    Ok(s.to_owned())
}

impl TryFrom<SafeValue> for bool {
    type Error = SafeError;

    fn try_from(value: SafeValue) -> Result<Self, Self::Error> {
        value.as_bool()
    }
}

impl TryFrom<SafeValue> for i32 {
    type Error = SafeError;

    fn try_from(value: SafeValue) -> Result<Self, Self::Error> {
        value.as_i32()
    }
}

impl TryFrom<SafeValue> for u8 {
    type Error = SafeError;

    fn try_from(value: SafeValue) -> Result<Self, Self::Error> {
        value.as_u8()
    }
}

impl TryFrom<SafeValue> for f32 {
    type Error = SafeError;

    fn try_from(value: SafeValue) -> Result<Self, Self::Error> {
        value.as_f32()
    }
}

impl TryFrom<SafeValue> for f64 {
    type Error = SafeError;

    fn try_from(value: SafeValue) -> Result<Self, Self::Error> {
        value.as_f64()
    }
}

impl TryFrom<SafeValue> for flags::EngineWarnings {
    type Error = SafeError;

    fn try_from(value: SafeValue) -> Result<Self, Self::Error> {
        Ok(Self::from_bits_truncate(value.as_i32()?))
    }
}

impl TryFrom<SafeValue> for flags::Flags {
    type Error = SafeError;

    fn try_from(value: SafeValue) -> Result<Self, Self::Error> {
        Ok(Self::from_bits_truncate(value.as_i32()? as u32))
    }
}

impl TryFrom<SafeValue> for flags::SessionState {
    type Error = SafeError;

    fn try_from(value: SafeValue) -> Result<Self, Self::Error> {
        let v = value.as_i32()?;
        match num::FromPrimitive::from_i32(v) {
            Some(t) => Ok(t),
            None => Err(SafeError::Type(ValueError::InvalidEnumValue(v))),
        }
    }
}

impl TryFrom<SafeValue> for flags::TrackLocation {
    type Error = SafeError;

    fn try_from(value: SafeValue) -> Result<Self, Self::Error> {
        let v = value.as_i32()?;
        match num::FromPrimitive::from_i32(v) {
            Some(t) => Ok(t),
            None => Err(SafeError::Type(ValueError::InvalidEnumValue(v))),
        }
    }
}

impl TryFrom<SafeValue> for flags::TrackSurface {
    type Error = SafeError;

    fn try_from(value: SafeValue) -> Result<Self, Self::Error> {
        let v = value.as_i32()?;
        match num::FromPrimitive::from_i32(v) {
            Some(t) => Ok(t),
            None => Err(SafeError::Type(ValueError::InvalidEnumValue(v))),
        }
    }
}

impl TryFrom<SafeValue> for flags::CarLeftRight {
    type Error = SafeError;

    fn try_from(value: SafeValue) -> Result<Self, Self::Error> {
        let v = value.as_i32()?;
        match num::FromPrimitive::from_i32(v) {
            Some(t) => Ok(t),
            None => Err(SafeError::Type(ValueError::InvalidEnumValue(v))),
        }
    }
}

impl TryFrom<SafeValue> for flags::CameraState {
    type Error = SafeError;

    fn try_from(value: SafeValue) -> Result<Self, Self::Error> {
        Ok(Self::from_bits_truncate(value.as_i32()?))
    }
}

impl TryFrom<SafeValue> for flags::PitSvcFlags {
    type Error = SafeError;

    fn try_from(value: SafeValue) -> Result<Self, Self::Error> {
        Ok(Self::from_bits_truncate(value.as_i32()?))
    }
}

impl TryFrom<SafeValue> for flags::PitSvcStatus {
    type Error = SafeError;

    fn try_from(value: SafeValue) -> Result<Self, Self::Error> {
        let v = value.as_i32()?;
        match num::FromPrimitive::from_i32(v) {
            Some(t) => Ok(t),
            None => Err(SafeError::Type(ValueError::InvalidEnumValue(v))),
        }
    }
}

impl TryFrom<SafeValue> for flags::PaceMode {
    type Error = SafeError;

    fn try_from(value: SafeValue) -> Result<Self, Self::Error> {
        let v = value.as_i32()?;
        match num::FromPrimitive::from_i32(v) {
            Some(t) => Ok(t),
            None => Err(SafeError::Type(ValueError::InvalidEnumValue(v))),
        }
    }
}

impl TryFrom<SafeValue> for flags::PaceFlags {
    type Error = SafeError;

    fn try_from(value: SafeValue) -> Result<Self, Self::Error> {
        Ok(Self::from_bits_truncate(value.as_i32()?))
    }
}
