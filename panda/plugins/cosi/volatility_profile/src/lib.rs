use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    fs::{self, File},
    io::BufReader,
    path::Path,
};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct VolatilityBaseType {
    pub size: i64,
    pub signed: bool,
    pub kind: String,
    pub endian: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct VolatilityEnum {
    pub size: i64,
    pub base: String,
    pub constants: HashMap<String, i64>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct VolatilitySymbol {
    #[serde(rename = "type")]
    pub type_val: Option<VolatilityType>,
    pub address: u64,
    pub constant_data: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum VolatilityType {
    Base {
        name: String,
    },

    Array {
        count: u64,
        subtype: Box<VolatilityType>,
    },

    Pointer {
        subtype: Box<VolatilityType>,
    },

    Struct {
        name: String,
    },

    Enum {
        name: String,
    },

    Union {
        name: String,
    },

    Bitfield {
        bit_position: i64,
        bit_length: u64,

        #[serde(rename = "type")]
        base_type: Box<VolatilityType>,
    },

    Function,
}

impl fmt::Display for VolatilityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VolatilityType::Base { name } => f.write_str(&name),
            VolatilityType::Array { count, subtype } => {
                write!(f, "{}[{}]", subtype.to_string(), count)
            }
            VolatilityType::Pointer { subtype } => write!(f, "{}*", subtype),
            VolatilityType::Struct { name } => write!(f, "struct {}", name),
            VolatilityType::Enum { name } => write!(f, "enum {}", name),
            VolatilityType::Union { name } => write!(f, "union {}", name),
            VolatilityType::Bitfield {
                bit_position,
                bit_length,
                base_type,
            } => write!(
                f,
                "(bitfield {}[{}..{}])",
                base_type,
                bit_position,
                (*bit_position as u64) + bit_length
            ),
            VolatilityType::Function => write!(f, "func_ptr"),
        }
    }
}

impl VolatilityType {
    pub fn to_string(&self) -> String {
        match self {
            VolatilityType::Base { name } => name.clone(),
            VolatilityType::Array { count, subtype } => {
                format!("{}[{}]", subtype.to_string(), count)
            }
            VolatilityType::Pointer { subtype } => format!("{}*", subtype.to_string()),
            VolatilityType::Struct { name: _ } => todo!(),
            VolatilityType::Enum { name: _ } => todo!(),
            VolatilityType::Union { name: _ } => todo!(),
            VolatilityType::Bitfield {
                bit_position: _,
                bit_length: _,
                base_type: _,
            } => todo!(),
            VolatilityType::Function => todo!(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct VolatilityStructField {
    #[serde(rename = "type")]
    pub type_val: Option<VolatilityType>,
    pub offset: i64,
    pub anonymous: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct VolatilityStruct {
    pub size: i64,
    pub fields: BTreeMap<String, VolatilityStructField>,
    pub kind: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SourceMetadata {
    pub kind: String,
    pub name: String,
    pub hash_type: String,
    pub hash_value: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UnixMetadata {
    pub symbols: Vec<SourceMetadata>,
    pub types: Vec<SourceMetadata>,
}

/// Windows ISF metadata: identifies the ntoskrnl PDB the symbol table was built from.
#[derive(Serialize, Deserialize, Debug)]
pub struct WindowsPdb {
    #[serde(rename = "GUID")]
    pub guid: String,
    pub age: i64,
    pub database: String,
    #[serde(default)]
    pub machine_type: Option<i64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WindowsMetadata {
    pub pdb: WindowsPdb,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Producer {
    pub name: String,
    pub version: String,
}

/// Top-level ISF metadata. Volatility3 emits exactly one of `linux`/`windows`/`mac`
/// depending on the OS the table was generated for, so all are optional. Unknown
/// producer fields (e.g. `datetime`) are ignored by serde.
#[derive(Serialize, Deserialize, Debug)]
pub struct VolatilityMetadata {
    #[serde(default)]
    pub linux: Option<UnixMetadata>,
    #[serde(default)]
    pub windows: Option<WindowsMetadata>,
    pub producer: Producer,
    pub format: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VolatilityJson {
    pub metadata: VolatilityMetadata,
    pub base_types: HashMap<String, VolatilityBaseType>,
    pub user_types: HashMap<String, VolatilityStruct>,
    pub enums: HashMap<String, VolatilityEnum>,
    pub symbols: HashMap<String, VolatilitySymbol>,
}

impl VolatilityJson {
    pub fn from_compressed_file(filename: impl AsRef<Path>) -> VolatilityJson {
        //pub fn from_compressed_file(filename: std::fs::File) -> VolatilityJson {
        let file = File::open(filename).unwrap();
        if file.metadata().unwrap().len() == 0 {
            panic!("cosi volatility profile empty");
        }

        let mut f = BufReader::new(file);
        let mut decomp = Vec::new();
        lzma_rs::xz_decompress(&mut f, &mut decomp).unwrap();
        let s = String::from_utf8_lossy(&decomp);
        serde_json::from_str(&s).unwrap()
    }

    pub fn from_file(filename: impl AsRef<Path>) -> VolatilityJson {
        let contents = fs::read_to_string(filename).unwrap();
        serde_json::from_str(&contents).unwrap()
    }

    pub fn enum_from_name(&self, name: &str) -> Option<&VolatilityEnum> {
        self.enums.get(name)
    }

    pub fn base_type_from_name(&self, name: &str) -> Option<&VolatilityBaseType> {
        self.base_types.get(name)
    }

    pub fn symbol_from_name(&self, name: &str) -> Option<&VolatilitySymbol> {
        self.symbols.get(name)
    }

    pub fn type_from_name(&self, name: &str) -> Option<&VolatilityStruct> {
        self.user_types.get(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Regression test for Windows ISF deserialization (panda-plus Win10/11 fork).
    // Skips gracefully if the symbol store isn't present (e.g. CI elsewhere).
    #[test]
    fn load_windows_isf() {
        // Set WIN_ISF_STORE to a directory of Volatility3 Windows ISF *.json.xz
        // tables (named <PDB-GUID>-<age>.json.xz) to run this regression test.
        let store = match std::env::var("WIN_ISF_STORE") {
            Ok(s) => s,
            Err(_) => {
                eprintln!("skip load_windows_isf: set WIN_ISF_STORE to an ISF directory to run");
                return;
            }
        };
        let tables = [
            "953A8DE880B0818C32DA2DEC1D79C2D9-1.json.xz", // tiny11 / 26100
            "40B8DB4FCF8B9D0352BFF2EF2903CB89-1.json.xz", // tiny10 / 19044
        ];
        for t in tables {
            let p = format!("{store}/{t}");
            if !Path::new(&p).exists() {
                eprintln!("skip (missing): {p}");
                continue;
            }
            let j = VolatilityJson::from_compressed_file(&p);
            let win = j.metadata.windows.as_ref().expect("windows metadata parsed");
            let ep = j.type_from_name("_EPROCESS").expect("_EPROCESS present");
            println!(
                "{t}: pdb={} guid={} age={} types={} symbols={} _EPROCESS.size={} ImageFileName@{} ActiveProcessLinks@{}",
                win.pdb.database,
                win.pdb.guid,
                win.pdb.age,
                j.user_types.len(),
                j.symbols.len(),
                ep.size,
                ep.fields["ImageFileName"].offset,
                ep.fields["ActiveProcessLinks"].offset,
            );
            assert!(j.symbol_from_name("PsActiveProcessHead").is_some());
            assert!(j.symbol_from_name("PsLoadedModuleList").is_some());
        }
    }
}
