use rand::Rng;
use std::convert::TryInto;
use std::env;
use std::io::prelude::*;
use std::io::Cursor;
use std::path::Path;

use hyper::client::HttpConnector;
use hyper::Client;
use hyper::{Body, Method, Request, Response};
use plist::{Dictionary, Value};

// Crypto
use ed25519_dalek::{Digest, SecretKey, Sha512};
use sha1::Sha1;
use srp::client::{srp_private_key, SrpClient};
use srp::groups::G_2048;
use x25519_dalek::EphemeralSecret;

// AES Crypto
use aead::{generic_array::GenericArray, Aead, NewAead};
use aes::{block_cipher_trait::generic_array::typenum::U16, Aes128};
use aes_ctr::stream_cipher::{NewStreamCipher, SyncStreamCipher};
use aes_ctr::Aes128Ctr;
use aes_gcm::AesGcm;
// Default 128Gcm is only 12 byte nonce, we need 16 byte
type Aes128Gcm = AesGcm<Aes128, U16>;

async fn step0(client: &Client<HttpConnector>, host_ip: &String) -> Response<Body> {
    let request = Request::builder()
        .method(Method::POST)
        .uri(["http://", host_ip.as_str(), ":7000/pair-pin-start"].concat())
        .header("User-Agent", "AirPlay/320.20")
        .header("Connection", "keep-alive")
        .body(Body::empty())
        .unwrap();
    client.request(request).await.unwrap()
}

async fn step1(
    client: &Client<HttpConnector>,
    host_ip: &String,
    username: &String,
) -> (Response<Body>, Vec<u8>, Vec<u8>) {
    // Use plist::Dictionary because I couldn't figure out how
    // to convert a std::HashMap to a plist using Value::from()
    let mut pair_data = Dictionary::new();
    pair_data.insert("user".to_string(), Value::String(username.to_string()));
    pair_data.insert("method".to_string(), Value::String("pin".to_string()));
    let req_plist = Value::from(pair_data);

    // Convert the plist into binary
    let mut req_data = Vec::new();
    let writer = Cursor::new(&mut req_data);
    Value::to_writer_binary(&req_plist, writer).unwrap();

    let request = Request::builder()
        .method(Method::POST)
        .uri(["http://", host_ip.as_str(), ":7000/pair-setup-pin"].concat())
        .header("Content-Type", "application/x-apple-binary-plist")
        .header("Content-Length", 85)
        .header("User-Agent", "AirPlay/320.20")
        .header("Connection", "keep-alive")
        .body(Body::from(req_data))
        .unwrap();
    let mut resp = client.request(request).await.unwrap();
    let body = hyper::body::to_bytes(resp.body_mut())
        .await
        .unwrap()
        .to_vec();

    // Parse the response data as a plist
    // then extract the values as individual variables
    let reader = Cursor::new(&body);
    let plist = Value::from_reader(reader).unwrap();
    let salt = plist
        .as_dictionary()
        .and_then(|dict| dict.get("salt"))
        .and_then(|data| data.as_data())
        .unwrap();
    let pk = plist
        .as_dictionary()
        .and_then(|dict| dict.get("pk"))
        .and_then(|data| data.as_data())
        .unwrap();

    // pk and salt are &[u8], can't return due to lifetimes
    (resp, Vec::from(pk), Vec::from(salt))
}

async fn step2(
    client: &Client<HttpConnector>,
    host_ip: &String,
    unique_id: &[u8],
    a: &[u8],
    pin: &Vec<u8>,
    pk: &Vec<u8>,
    salt: &Vec<u8>,
) -> (Response<Body>, Vec<u8>, Vec<u8>) {
    // Feed SRP: unique_id, pin, salt, a, pk to receive proof (m1)
    let srp_client = SrpClient::<Sha1>::new(&a, &G_2048);
    let big_a = srp_client.get_a_pub();
    let salt_u8: &[u8] = &salt;
    let x = srp_private_key::<Sha1>(&unique_id, &pin, &salt_u8);
    let verifier = srp_client
        .process_reply(&unique_id, &salt_u8, &x, &pk)
        .unwrap();
    let m1 = verifier.get_proof();
    let k = verifier.get_key();

    // Use plist::Dictionary because I couldn't figure out how
    // to convert a std::HashMap to a plist using Value::from()
    let mut pair_data = Dictionary::new();
    pair_data.insert("pk".to_string(), Value::Data(big_a.to_vec()));
    pair_data.insert("proof".to_string(), Value::Data(m1.to_vec()));
    let req_plist = Value::from(pair_data);

    // Convert the plist into binary
    let mut req_data = Vec::new();
    let writer = Cursor::new(&mut req_data);
    Value::to_writer_binary(&req_plist, writer).unwrap();

    // Send off to apple tv to receive it's proof back
    let request = Request::builder()
        .method(Method::POST)
        .uri(["http://", host_ip.as_str(), ":7000/pair-setup-pin"].concat())
        .header("Content-Type", "application/x-apple-binary-plist")
        .header("Content-Length", 347)
        .header("User-Agent", "AirPlay/320.20")
        .header("Connection", "keep-alive")
        .body(Body::from(req_data))
        .unwrap();
    let mut resp = client.request(request).await.unwrap();
    let body = hyper::body::to_bytes(resp.body_mut())
        .await
        .unwrap()
        .to_vec();

    // Parse the response data as a plist
    // then extract the values as individual variables
    let reader = Cursor::new(&body);
    let plist = Value::from_reader(reader).unwrap();
    let proof = plist
        .as_dictionary()
        .and_then(|dict| dict.get("proof"))
        .and_then(|data| data.as_data())
        .unwrap();

    // proof is &[u8], can't return due to lifetimes
    (resp, Vec::from(proof), k)
}

async fn step3(
    client: &Client<HttpConnector>,
    host_ip: &String,
    _unique_id: &[u8],
    a: &[u8],
    k: &[u8],
) -> Response<Body> {
    let aes_key = {
        let mut d = Sha512::new();
        d.input("Pair-Setup-AES-Key".to_string());
        d.input(&k);
        let result = d.result();
        let mut result_vec = result.to_vec();
        result_vec.truncate(16);
        result_vec
    };
    let aes_iv = {
        let mut d = Sha512::new();
        d.input("Pair-Setup-AES-IV".to_string());
        d.input(&k);
        let result = d.result();
        let mut result_vec = result.to_vec();
        result_vec.truncate(16);
        let l = result_vec.len();
        result_vec[l - 1] += 0x01;
        result_vec
    };
    let pub_a = {
        let secret_key = SecretKey::from_bytes(&a).unwrap();
        let public_key: ed25519_dalek::PublicKey = (&secret_key).into();
        public_key.to_bytes()
    };

    let aes_key_u8: &[u8] = &aes_key;
    let aes_iv_u8: &[u8] = &aes_iv;

    let key = GenericArray::clone_from_slice(aes_key_u8);
    let aead = Aes128Gcm::new(key);
    let nonce = GenericArray::from_slice(aes_iv_u8);
    let ciphertext = aead
        .encrypt(nonce, pub_a.as_ref())
        .expect("encryption failure!");
    let ciphertext_vec = ciphertext.to_vec();
    let (epk, tag) = ciphertext_vec.as_slice().split_at(32);

    // Use plist::Dictionary because I couldn't figure out how
    // to convert a std::HashMap to a plist using Value::from()
    let mut pair_data = Dictionary::new();
    pair_data.insert("epk".to_string(), Value::Data(epk.to_vec()));
    pair_data.insert("authTag".to_string(), Value::Data(tag.to_vec()));
    let req_plist = Value::from(pair_data);

    // Convert the plist into binary
    let mut req_data = Vec::new();
    let writer = Cursor::new(&mut req_data);
    Value::to_writer_binary(&req_plist, writer).unwrap();

    // Send off to apple tv to receive it's proof back
    let request = Request::builder()
        .method(Method::POST)
        .uri(["http://", host_ip.as_str(), ":7000/pair-setup-pin"].concat())
        .header("Content-Type", "application/x-apple-binary-plist")
        .header("Content-Length", 116)
        .header("User-Agent", "AirPlay/320.20")
        .header("Connection", "keep-alive")
        .body(Body::from(req_data))
        .unwrap();
    let resp = client.request(request).await.unwrap();
    return resp;
}

async fn pair(host_ip: &String, a: &[u8]) {
    // Socket connection that will be used through all steps
    let client = Client::new();

    // -------------------------------------------------------------------- //
    // Step 0 - INITIATE PAIRING
    let resp = step0(&client, &host_ip).await;
    println!("Step 0: {}", resp.status());

    // -------------------------------------------------------------------- //
    // Step 1 - CONFIRM PIN
    // user: <Up to 16 unique bytes>
    // TODO: Randomly generate this and save with secret key <a>
    let unique_id_string = "366B4165DD64AD3A".to_string();
    let unique_id = unique_id_string.replace("\n", "").into_bytes();
    let (resp, pk, salt) = step1(&client, &host_ip, &unique_id_string).await;
    println!("Step 1: {}", resp.status());

    // -------------------------------------------------------------------- //
    // Step 2 - RUN SRP
    // Get the pin that is generated by the ATV
    let mut pin_string = String::new();
    print!("Enter generated PIN: ");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_line(&mut pin_string).unwrap();
    let pin = pin_string.replace("\n", "").into_bytes();

    // Feed SRP all it needs
    let (resp, _proof, k) = step2(&client, &host_ip, &unique_id, &a, &pin, &pk, &salt).await;
    println!("Step 2: {}", resp.status());

    // -------------------------------------------------------------------- //
    // Step 3 - RUN AES
    step3(&client, &host_ip, &unique_id, &a, &k).await;
    println!("Step 3: {}", resp.status());
    println!("Assuming every step returned 200 OK, This device is now registered on the ATV");
}

async fn verify(host_ip: &String, a: &[u8]) {
    // Socket connection that will be used through all steps
    let client = Client::new();

    // -------------------------------------------------------------------- //
    // Step 1 - CREATE NEW KEYS
    // Generate ephemeral pub and priv using x25519 ECDH
    let mut rng = rand::thread_rng();
    let priv_v = EphemeralSecret::new(&mut rng);
    let pub_v = x25519_dalek::PublicKey::from(&priv_v);
    let pub_v = pub_v.as_bytes();

    let pub_a = {
        let secret_key = SecretKey::from_bytes(&a).unwrap();
        let public_key: ed25519_dalek::PublicKey = (&secret_key).into();
        public_key.to_bytes()
    };

    let body_data = {
        let mut header = b"\x01\x00\x00\x00".to_vec();
        header.append(&mut pub_v.to_vec());
        header.append(&mut pub_a.to_vec());
        header
    };

    // Send off to apple tv to receive it's proof back
    let request = Request::builder()
        .method(Method::POST)
        .uri(["http://", host_ip.as_str(), ":7000/pair-verify"].concat())
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", 68)
        .header("User-Agent", "AirPlay/320.20")
        .header("Connection", "keep-alive")
        .body(Body::from(body_data))
        .unwrap();
    let mut resp = client.request(request).await.unwrap();
    let body = hyper::body::to_bytes(resp.body_mut())
        .await
        .unwrap()
        .to_vec();
    println!("Step 1: {}", resp.status());

    // TODO: Verify content-length is 96 bytes
    // first 32 bytes are the public key
    // remaining data "should" be 64 bytes (but not always??)
    let (atv_pub_val, atv_data) = body.as_slice().split_at(32);

    // -------------------------------------------------------------------- //
    // Step 2 - RUN AES
    let atv_pub = {
        let atv_pub: [u8; 32] = atv_pub_val.try_into().expect("unable to convert atv_pub");
        let atv_pub_key = x25519_dalek::PublicKey::from(atv_pub);
        atv_pub_key
    };

    let shared_secret = priv_v.diffie_hellman(&atv_pub);
    let keypair = {
        let secret: ed25519_dalek::SecretKey = ed25519_dalek::SecretKey::from_bytes(&a).unwrap();
        let public: ed25519_dalek::PublicKey =
            ed25519_dalek::PublicKey::from_bytes(&pub_a).unwrap();
        ed25519_dalek::Keypair { secret, public }
    };

    let signed = {
        let mut concat = pub_v.to_vec().clone();
        let atv_pub_u8: &[u8] = &atv_pub_val;
        concat.append(&mut atv_pub_u8.to_vec());
        let signature = keypair.sign(&concat);
        signature.to_bytes()
    };
    let aes_key_hash = {
        let mut d = Sha512::new();
        d.input("Pair-Verify-AES-Key".to_string());
        d.input(shared_secret.as_bytes());
        let result = d.result();
        let mut result_vec = result.to_vec();
        result_vec.truncate(16);
        result_vec
    };
    let aes_iv_hash = {
        let mut d = Sha512::new();
        d.input("Pair-Verify-AES-IV".to_string());
        d.input(shared_secret.as_bytes());
        let result = d.result();
        let mut result_vec = result.to_vec();
        result_vec.truncate(16);
        result_vec
    };
    let aes_key = GenericArray::from_slice(&aes_key_hash);
    let aes_iv = GenericArray::from_slice(&aes_iv_hash);
    let mut cipher = Aes128Ctr::new(&aes_key, &aes_iv);

    let mut atv_data_encrypted = atv_data.to_vec();
    cipher.apply_keystream(&mut atv_data_encrypted);
    let mut signature = signed.clone();
    cipher.apply_keystream(&mut signature);
    let body_data = {
        let mut header = b"\x00\x00\x00\x00".to_vec();
        header.append(&mut signature.to_vec());
        header
    };

    // Send off to apple tv to receive it's proof back
    let request = Request::builder()
        .method(Method::POST)
        .uri(["http://", host_ip.as_str(), ":7000/pair-verify"].concat())
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", 68)
        .header("User-Agent", "AirPlay/320.20")
        .header("Connection", "keep-alive")
        .body(Body::from(body_data))
        .unwrap();
    let resp = client.request(request).await.unwrap();
    println!("Step 2: {}", resp.status());
    println!("Authentication has been verified, socket is good to use");
}

async fn get_secret() -> Vec<u8> {
    let a: Vec<u8> = {
        if Path::new("secret.plist").exists() {
            let plist_test = Value::from_file("secret.plist").unwrap();
            let a = plist_test
                .as_dictionary()
                .and_then(|dict| dict.get("a"))
                .and_then(|data| data.as_data())
                .unwrap();
            a.to_vec()
        } else {
            let a = rand::thread_rng().gen::<[u8; 32]>();
            let ret_a = a.to_vec();

            // Use plist::Dictionary because I couldn't figure out how
            // to convert a std::HashMap to a plist using Value::from()
            let mut pair_data = Dictionary::new();
            pair_data.insert("a".to_string(), Value::Data(ret_a));
            let req_plist = Value::from(pair_data);

            // Convert the plist into binary
            let mut binary_plist = Vec::new();
            let writer = Cursor::new(&mut binary_plist);
            Value::to_writer_binary(&req_plist, writer).unwrap();

            // Save secret key to file
            let plistfile = std::fs::File::create("secret.plist").unwrap();
            let mut bufwriter = std::io::BufWriter::new(plistfile);
            bufwriter.write_all(&binary_plist).unwrap();

            a.to_vec()
        }
    };
    return a;
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = env::args().collect();

    // IP Address of the ATV connecting to
    // TODO Error checking
    let host_ip = &args[1].to_string();

    // Randomly generated secret key. Will attempt to read from file first.
    // If lost, pairing/authentication will need to be redone.
    let a = get_secret().await;

    pair(&host_ip, &a).await;
    verify(&host_ip, &a).await;

    return Ok(());
}
