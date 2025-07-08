use league_toolkit::core::meta::BinPropertyKind::{Container, Embedded, UnorderedContainer};
use league_toolkit::core::meta::{BinProperty, BinTree, PropertyValueEnum};
use league_toolkit::core::render::texture::format;
use league_toolkit::core::wad::{
    Wad, WadBuilder, WadBuilderError, WadChunk, WadChunkBuilder, WadChunkCompression, WadDecoder,
    WadError,
};
use league_toolkit::league_file;
use serde_json::Value;
use simple_stopwatch::Stopwatch;

use std::collections::HashMap;
use std::fs;
use std::hash::Hash;
use std::io::{Cursor, Read};
use std::path::Path;
use std::sync::Mutex;
use std::{env, result};
use xxhash_rust::xxh64::xxh64;
struct Storage {
    entry_hashes: Mutex<HashMap<u64, String>>, // for entry files (string to hash)
    game_hashes: Mutex<HashMap<u64, String>>,  // for game files (hash to string)
}

fn hash_add_entry(key: u64, value: String, storage: &Storage) {
    let mut entry_hashes = storage.entry_hashes.lock().unwrap();
    entry_hashes.insert(key, value);
}

fn hash_add_game(key: u64, value: String, storage: &Storage) {
    let mut game_hashes = storage.game_hashes.lock().unwrap();
    game_hashes.insert(key, value);
}

fn download_file(url: &str) -> Result<Box<[u8]>, String> {
    let client = reqwest::blocking::Client::new();
    let response = client
        .get(url)
        .header("User-Agent", "Rust-Client")
        .send()
        .map_err(|e| e.to_string())?;

    if !response.status().is_success() {
        return Err(format!("Failed to download file: {}", response.status()));
    }

    let bytes = response.bytes().map_err(|e| e.to_string())?;
    Ok(bytes.to_vec().into_boxed_slice())
}

fn sync_hash_files(url: &str, appdatadir: &str) -> Result<(), String> {
    let client = reqwest::blocking::Client::new();
    let response = client
        .get(url)
        .header("User-Agent", "Rust-Client")
        .send()
        .map_err(|e| e.to_string())?;

    let v: Value = response.json().map_err(|e| e.to_string())?;

    let sha = v
        .get("sha")
        .and_then(|s| s.as_str())
        .ok_or("Missing 'sha' field in response".to_string())?;

    let download_url = v
        .get("download_url")
        .and_then(|s| s.as_str())
        .ok_or("Missing 'download_url' field in response".to_string())?;

    let file_name = url
        .split('/')
        .last()
        .ok_or("Failed to extract file name from URL".to_string())?;

    let file_path = format!("{}/{}", appdatadir, file_name);

    // if the file already exists, check if the sha matches
    if Path::new(&file_path).exists() {
        let existing_sha =
            fs::read_to_string(format!("{}.sha", file_path)).map_err(|e| e.to_string())?;
        if existing_sha.trim() == sha {
            println!(
                "File {} already exists and SHA matches, skipping download.",
                file_name
            );
            return Ok(());
        } else {
            let data = download_file(download_url)
                .map_err(|e| format!("Failed to download file: {}", e))?;
            fs::write(&file_path, data).map_err(|e| e.to_string())?;
            let sha_path = format!("{}.sha", file_path);
            fs::write(&sha_path, sha).map_err(|e| e.to_string())?;
        }
    } else {
        let data =
            download_file(download_url).map_err(|e| format!("Failed to download file: {}", e))?;
        fs::write(&file_path, data).map_err(|e| e.to_string())?;
        let sha_path = format!("{}.sha", file_path);
        fs::write(&sha_path, sha).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn main() {
    let appdatadir = "C:/Code/grust/hashes";
    let storage = Storage {
        entry_hashes: Mutex::new(HashMap::new()),
        game_hashes: Mutex::new(HashMap::new()),
    };

    let git_links: Vec<&str> = vec![
        "https://api.github.com/repos/CommunityDragon/Data/contents/hashes/lol/hashes.binentries.txt",
        "https://api.github.com/repos/CommunityDragon/Data/contents/hashes/lol/hashes.game.txt.0",
        "https://api.github.com/repos/CommunityDragon/Data/contents/hashes/lol/hashes.game.txt.1",
    ];
    for url in git_links {
        let _ = sync_hash_files(url, appdatadir);
    }

    let hash_files: Vec<String> = vec![
        format!("{}/hashes.binentries.txt", appdatadir),
        format!("{}/hashes.game.txt.0", appdatadir),
        format!("{}/hashes.game.txt.1", appdatadir),
    ];
    let mut sw = Stopwatch::start_new();

    for file in hash_files {
        let file_path = file.clone();
        if let Ok(data) = fs::read(&file_path) {
            if let Ok(text) = String::from_utf8(data) {
                for line in text.lines() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    // Use different hashtables depending on file type
                    if file_path.contains("binentries") {
                        // entry: string to hash (parse hex string as hash)
                        if let Some((hex, name)) = line.split_once(' ') {
                            if let Ok(hash) = u64::from_str_radix(hex.trim(), 16) {
                                hash_add_entry(hash, name.trim().to_string(), &storage);
                            }
                        }
                    } else if file_path.contains("game.txt") {
                        // game: hash to string (parse hex string as hash)
                        if let Some((hex, name)) = line.split_once(' ') {
                            if let Ok(hash) = u64::from_str_radix(hex.trim(), 16) {
                                hash_add_game(hash, name.trim().to_string(), &storage);
                            }
                        }
                    }
                }
            } else {
                println!("Failed to parse file as UTF-8 text: {}", file_path);
            }
        } else {
            println!("Failed to read file: {}", file_path);
        }
    }
    // Print the number of entries in each storage
    let entry_hashes = storage.entry_hashes.lock().unwrap();
    let game_hashes = storage.game_hashes.lock().unwrap();
    println!("Entry hashes: {}", entry_hashes.len());
    println!("Game hashes: {}", game_hashes.len());

    // Print the time taken to process the files
    println!("Time taken to process files: {} ms", sw.ms());

    // Example usage of the hash tables
    // get file path from aed510d4c996ed6d
    sw.restart();
    let example_hash: u64 = 0xaed510d4c996ed6d;
    if let Some(path) = game_hashes.get(&example_hash) {
        println!("File path for hash {:016X}: {}", example_hash, path);
        println!("Time taken to find file path: {} ms", sw.ms());
    } else {
        println!("No file path found for hash {:016X}", example_hash);
    }
}

/*  mod hashtable;

fn fnv(text: &str) -> u32 {
    let binding = text;
    let input = binding.as_bytes();
    const FNV_OFFSET_BASIS: u32 = 0x811c9dc5;
    const FNV_PRIME: u32 = 0x01000193;
    let mut hash = FNV_OFFSET_BASIS;
    for &byte in input {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn parse_bin(data: Box<[u8]>, files_to_extract: &mut HashSet<u64>) {
    // Example: just print the size of the bin data
    // Add your bin parsing logic here
    let mut cursor = Cursor::new(data.clone());

    let mut bin = match BinTree::from_reader(&mut cursor) {
        Ok(bin) => bin,
        Err(e) => {
            println!("Error reading bin data: {:?}", e);
            return;
        }
    };

    // bin.dependencies.iter().for_each(|dep| {
    //     println!("Dependency: {}", dep);
    // });
    files_to_extract.extend(bin.dependencies.iter().map(|dep| xxh64(dep.as_bytes(), 0)));

    files_to_extract.extend(get_all_strings_with_extensions(&bin));
}

pub struct StructValue {
    pub class_hash: u32,
    pub properties: HashMap<u32, BinProperty>,
}

//recursively traverse bin properties and return a list of all strings that have any extension (can be split by .)
fn get_all_strings_with_extensions(bin: &BinTree) -> Vec<u64> {
    let mut strings_with_extensions = Vec::new();
    for (_hash, obj) in bin.objects.iter() {
        for (key, prop) in obj.properties.iter() {
            strings_with_extensions.extend(process_property(prop, &strings_with_extensions));
        }
    }
    strings_with_extensions
}
fn process_property(prop: &BinProperty, _files_to_extract: &Vec<u64>) -> Vec<u64> {
    let mut results = Vec::new();
    if let PropertyValueEnum::String(s) = &prop.value {
        let clean = s.0.trim_matches('"').to_lowercase();
        if clean.contains('.') {
            let hash = xxh64(clean.as_bytes(), 0);
            results.push(hash);
        }
    } else if let PropertyValueEnum::Embedded(embedded) = &prop.value {
        for (_key, embedded_prop) in embedded.0.properties.iter() {
            results.extend(process_property(embedded_prop, &Vec::new()));
        }
    } else if let PropertyValueEnum::Container(container) = &prop.value {
        for item in &container.items {
            if let PropertyValueEnum::Embedded(embedded) = item {
                for (_key, embedded_prop) in embedded.0.properties.iter() {
                    results.extend(process_property(embedded_prop, &Vec::new()));
                }
            } else if let PropertyValueEnum::Struct(s) = item {
                for (_key, struct_prop) in s.properties.iter() {
                    results.extend(process_property(struct_prop, &Vec::new()));
                }
            } else if let PropertyValueEnum::String(s) = item {
                let clean = s.0.trim_matches('"').to_lowercase();
                if clean.contains('.') {
                    let hash = xxh64(clean.as_bytes(), 0);
                    results.push(hash);
                }
            } /*  else {
            println!("Unhandled property type: {:?}", item);
            println!("{:?}", prop.value);
            std::process::exit(0);
            }*/
        }
    } else if let PropertyValueEnum::UnorderedContainer(unordered_container) = &prop.value {
        for item in &unordered_container.0.items {
            if let PropertyValueEnum::Embedded(embedded) = item {
                for (_key, embedded_prop) in embedded.0.properties.iter() {
                    results.extend(process_property(embedded_prop, &Vec::new()));
                }
            }
        }
    } else if let PropertyValueEnum::Optional(optional) = &prop.value {
        if let Some(inner_prop) = &optional.value {
            if let PropertyValueEnum::String(s) = inner_prop.as_ref() {
                let clean = s.0.trim_matches('"').to_lowercase();
                if clean.contains('.') {
                    let hash = xxh64(clean.as_bytes(), 0);
                    results.push(hash);
                }
            }
        }
    }
    results
}

fn main() {
    // get sha checksum of the file
    let github_blob_url =
        "https://github.com/CommunityDragon/Data/blob/master/hashes/lol/hashes.binentries.txt";
    let checksum = hashtable::get_checksum(github_blob_url);

    match checksum {
        Ok(sum) => println!("Checksum: {}", sum),
        Err(e) => println!("Checksum error: {}", e),
    }

    //

    // let args: Vec<String> = env::args().collect();

    // if args.len() < 2 {
    //     println!("Drag and drop a .wad or .fantome or installed folder onto the .exe");
    //     return;
    // }

    // let path = Path::new(&args[1]);

    // let mut files_to_extract: HashSet<u64> = HashSet::new();
    // // from the path, we can extract the champion name
    // let champion_name = path
    //     .file_name()
    //     .and_then(|s| s.to_str())
    //     .and_then(|s| s.split('.').next())
    //     .map(|s| s.to_lowercase())
    //     .unwrap_or_else(|| "unknown".to_string());
    // let champion_name = champion_name.as_str();
    // println!("{}", champion_name);

    // println!("Processing: {}", path.display());
    // if path.is_file() {
    //     let path_str = path.to_string_lossy().to_lowercase();
    //     if path_str.ends_with(".wad") || path_str.ends_with(".client") {
    //         let mut buf = Vec::new();
    //         if let Ok(mut file) = fs::File::open(path) {
    //             if let Ok(_) = file.read_to_end(&mut buf) {
    //                 process_wad(buf, &mut files_to_extract, champion_name);
    //             }
    //         }
    //     } else {
    //         println!("File detected, but not a .wad or .client file.");
    //     }
    // }
    // // files_to_extract
    // //     .iter()
    // //     .for_each(|hash| println!("File to extract: {:08X}", hash));
}

fn process_wad(buf: Vec<u8>, files_to_extract: &mut HashSet<u64>, champion_name: &str) {
    let cursor = Cursor::new(buf);
    let mut wad = match Wad::mount(cursor) {
        Ok(wad) => wad,
        Err(e) => {
            println!("Error mounting WAD file: {:?}", e);
            return;
        }
    };

    let bad_bin: Vec<u64> = vec![
        xxh64(
            format!("data/characters/{}/{}.bin", champion_name, champion_name).as_bytes(),
            0,
        ),
        xxh64(
            format!("data/characters/{}/skins/root.bin", champion_name).as_bytes(),
            0,
        ),
    ];
    // for hash in &bad_bin {
    //     println!("Bad bin hash: {:08X}", hash);
    // }

    let (mut decoder, chunks) = wad.decode();

    let mut chunk_count = 0;
    for (path_hash, chunk) in chunks {
        chunk_count += 1;
        // if bad_bin.contains(&path_hash) {
        //     println!("Skipping bad bin chunk: {:08X}", path_hash);
        //     continue;
        // }

        // only scan the header of the chunk, not the whole chunk

        match decoder.load_chunk_decompressed(chunk) {
            Ok(data) => {
                let filetype = league_file::LeagueFileKind::identify_from_bytes(&data);
                if let league_file::LeagueFileKind::PropertyBin = filetype {
                    let boxed_data: Box<[u8]> = data.into();
                    // println!("Chunk hash: {:08X}  {}", path_hash, path_hash);
                    parse_bin(boxed_data, files_to_extract);
                }
            }
            Err(e) => {
                println!("Error loading chunk: {:?}", e);
            }
        }
    }
    println!("Files to extract: {}", files_to_extract.len());

    println!("{} chunks in WAD", chunk_count);
}

// Hashmap to store the hash of the file and the path from path
*/
