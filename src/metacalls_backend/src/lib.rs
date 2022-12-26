use std::borrow::BorrowMut;
use std::{cell::RefCell, fmt::Debug};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use data_encoding::HEXUPPER;

use std::time::Duration;
use ic_cdk::api::management_canister::ecdsa::{ecdsa_public_key, EcdsaPublicKeyArgument, EcdsaKeyId, sign_with_ecdsa, SignWithEcdsaArgument, SignWithEcdsaResponse};
use ic_cdk::id;
use ic_cdk::timer::TimerId;


mod dos;
use dos::{guard_query_function, dos_set_timer_interval};
const DOS_INIT_FUNCTION:&str = "init_function";

const INIT_MC_TIMER_INTERVAL:u8 = 10;
const INIT_MC_TIME_TO_ARCHIVE:u64 = 10000000000;


const DEV_KEY_NAME:&str = "dfx_test_key";
const DEV_SIGN_CYCLES:u64 = 0;
const DEV_FILE_NAME:&str = "dev/pidentities";
const PROD_KEY_NAME:&str = "key_1";
const PROD_SIGN_CYCLES:u64 = 26_153_846_153;
const PROD_FILE_NAME:&str = "prod/pidentities";


thread_local! {
    static MESSAGES:RefCell<Messages> = RefCell::default();
    static PIDENTITIES:RefCell<PIdentities> = RefCell::default();
    static MC_TIMER_INTERVAL:RefCell<u8> = RefCell::new(INIT_MC_TIMER_INTERVAL);
    static MC_TIMER:RefCell<TimerId> = RefCell::default();
    static MC_TIME_TO_ARCHIVE:RefCell<u64> = RefCell::new(INIT_MC_TIME_TO_ARCHIVE);

}


pub async fn user_init_function(_arg:String) -> () {
    create_derived_identity(String::from("/")).await;
    dos_set_timer_interval(String::from("100")).await;


    MC_TIMER_INTERVAL.with(|refcell| {
        let timer_id = ic_cdk::timer::set_timer_interval(Duration::from_secs(*refcell.borrow() as u64), || ic_cdk::spawn(message_checker()));
        MC_TIMER.with(move |refcell| {
            refcell.replace(timer_id);
        })
    }); 

}



#[ic_cdk_macros::update]
async fn mc_set_time_to_archive_message(interval: String) -> String{
    let interval = interval.parse::<u64>().unwrap();
    MC_TIME_TO_ARCHIVE.with(|refcell| {
        refcell.replace(interval);
    });
    "ok".to_owned()
}

#[ic_cdk_macros::update]
pub async fn mc_set_timer_interval(interval: String) -> String {

    let interval = interval.parse::<u64>().unwrap();
    MC_TIMER.with( |refcell| {
        let timer_id = &mut *refcell.borrow_mut();
        ic_cdk::timer::clear_timer(*timer_id);
 
    });

    MC_TIMER.with(move |refcell| {
        let timer_id = ic_cdk::timer::set_timer_interval(Duration::from_secs(interval), || ic_cdk::spawn(message_checker()));
        refcell.replace(timer_id);
    });

   
    format!("ok")
}




async fn message_checker() {

    let current_ts = ic_cdk::api::time();

    MESSAGES.with(|refcell| {

        let messages = &mut *refcell.borrow_mut();

        let  x= &mut *messages.messages.borrow_mut();
        let mut keys_to_remove:Vec<String> = vec![];

        MC_TIME_TO_ARCHIVE.with (|refcell| {

            let time_to_archive = &*refcell.borrow();
            let time_to_archive = time_to_archive.clone();

            for key in x.keys() {
                let message = x.get(key).unwrap();
                if current_ts - message.get_created_ts() > time_to_archive {
                    keys_to_remove.insert(0, String::from(key));

                }
            }
        });

        for key in keys_to_remove {
            x.remove(&key);
        }

    });

}



#[ic_cdk_macros::update]
async fn create_message (original_message: String) -> String {
    if let Some(uuid) = ic_cdk::api::management_canister::main::raw_rand().await.ok() {        
        if let Some(message) = Message::new(&original_message, "/",  uuid) {
           return String::from(message.get_uuid())
        }
        else {
            return "".to_owned();
        }
    } 
    else {
        return "".to_owned();
    }   
}



#[ic_cdk_macros::update]
async fn create_message_for (original_message: String, signed_by: String) -> String {
    if let Some(uuid) = ic_cdk::api::management_canister::main::raw_rand().await.ok() {        
        if let Some(message) = Message::new(&original_message, &signed_by,  uuid) {
           return String::from(message.get_uuid())
        }
        else {
            return "".to_owned();
        }
    } 
    else {
        return "".to_owned();
    }   
}




#[ic_cdk_macros::update]
async fn sign_message (uuid: String) -> String {

    let mut message_hash = vec![];
    let mut derivation_path = vec![];
    
    (message_hash, derivation_path) =      MESSAGES.with(|refcell| {
        
        let messages = & *refcell.borrow();

        let x = & mut *messages.messages.borrow_mut();
        let message = x.get(&uuid);
    
        if let Some(message) = message {
            ( message.hashed_message.clone(), vec![message.signed_by.clone().into_bytes()])
        }
        else {
            (vec![], vec![])
        }
            
    });

    let key_id = EcdsaKeyId {
        curve: ic_cdk::api::management_canister::ecdsa::EcdsaCurve::Secp256k1,
        name: String::from(PIdentities::get_environment().key_name),
    };


    let arg = SignWithEcdsaArgument { 
        message_hash,
        derivation_path,
        key_id, 
    };

    let signature = sign_with_ecdsa(arg).await.ok();

    if let Some(signature) = signature {
        let signature = signature.0.signature;


        MESSAGES.with(move |refcell| {
    
            let messages = &mut *refcell.borrow_mut();

            let x = &mut *messages.messages.borrow_mut();

            let message = x.get(&uuid);
            
            if let Some(message) = message {
                let mut cloned_message = message.clone();
    
                let last_updated_ts = ic_cdk::api::time();
    
                let message_hash = message.hashed_message.clone();
                let derivation_path = vec![message.signed_by.clone().into_bytes()];
    
    
                cloned_message.set_last_updated_ts(last_updated_ts);
                cloned_message.set_status(MessageStatus::Signed);
                cloned_message.set_signature(signature);

    
                x.insert(uuid, cloned_message);
                "ok".to_owned()
            }
            else {
                "".to_owned()
            }        
        })

    } 
    else {
        "".to_owned()
    }
    
}


 
#[ic_cdk_macros::update]
async fn create_signed_message_with(original_message:String, signed_by: String) -> String {

    let uuid = create_message_for(original_message, signed_by).await;
    if uuid.eq_ignore_ascii_case("") {
        "".to_owned()
    }
    else {
        let cloned_uuid = uuid.clone();

        let result = sign_message(uuid).await;
        if result.eq_ignore_ascii_case("") {
            "".to_owned()
        }
        else {
            cloned_uuid
        }

    } 

}



#[ic_cdk_macros::update]
async fn create_signed_message(original_message:String) -> String {

    let uuid = create_message(original_message).await;
    if uuid.eq_ignore_ascii_case("") {
        "".to_owned()
    }
    else {
        let cloned_uuid = uuid.clone();

        let result = sign_message(uuid).await;
        if result.eq_ignore_ascii_case("") {
            "".to_owned()
        }
        else {
            cloned_uuid
        }

    } 

}




#[ic_cdk_macros::query (guard="guard_query_function")]
fn list_messages() -> String {

    MESSAGES.with(|refcell| {
        let mut ret_str = String::from("");

        let messages = &*refcell.borrow();

        let x = &*messages.messages.borrow();

        for key in x.keys() {
            let message = x.get(key).unwrap();
            let string_message = format!("{:?}, ", message);

            ret_str.push_str(&string_message);


        }
        ret_str
    })    
}



#[ic_cdk_macros::update]
async fn create_derived_identity(key_name:String) -> String {
    let derived_identity = PIdentity::new_derived_identity(key_name).await;
    derived_identity.get_key_name()
}

#[ic_cdk_macros::query(guard="guard_query_function")]
fn list_derived_identities() -> String {
    let v1= PIdentities::get_derived_identities();
    let mut ret_str = String::new();
    for i in v1 {
        ret_str.push_str(&format!("{},", i));
    }
    ret_str
}


#[ic_cdk_macros::query(guard="guard_query_function")]
fn get_derived_identity(key_name:String) -> String {
    if let Some(pid) = PIdentities::get_derived_identity(key_name) {
            format!("{:?}", pid)
    }
    else {
        "".to_owned()
    }
}



#[derive(Default, Debug, Clone)]
pub enum EnvironmentType {
    #[default] Dev,
    Prod,
}

#[derive( Debug, Clone)]
struct Environment {
    environment_type: EnvironmentType,
    key_name: String, 
    sign_cycles: u64,
    file_name: String,
}

impl Default for Environment {
    fn default() -> Self {
        let environment_type = EnvironmentType::default();
        Environment::from(environment_type)
    }
}


impl From<EnvironmentType> for Environment {
    fn from(environment_type: EnvironmentType) -> Self {
        match environment_type {
            EnvironmentType::Dev => {
                Self {
                    environment_type,
                    key_name: DEV_KEY_NAME.to_owned(),
                    sign_cycles: DEV_SIGN_CYCLES,
                    file_name: DEV_FILE_NAME.to_owned(),
                }
            },
            EnvironmentType::Prod => {
                Self {
                    environment_type,
                    key_name: PROD_KEY_NAME.to_owned(),
                    sign_cycles: PROD_SIGN_CYCLES,
                    file_name: PROD_FILE_NAME.to_owned(),
                }
            },
        }       
    }
}



#[derive(Debug, Default)]
pub struct PIdentities {
    pidentities: BTreeMap<String, PIdentity>,
    environment: Environment,
}


impl PIdentities {
    fn set_environment (&mut self, environment: Environment) {
        self.environment = environment;
    }

    fn get_environment () -> Environment{
        PIDENTITIES.with(|refcell| {
            let pids = &*refcell.borrow();
            pids.environment.clone()
        })
    }
}
impl PIdentities {

    pub fn switch_environment (environment_type: EnvironmentType) {

        PIDENTITIES.with(|refcell| {
            let pidentities = &mut *refcell.borrow_mut();
            pidentities.set_environment(Environment::from(environment_type));

        })
    }

    pub fn get_derived_identities() -> Vec<String> {        
        PIDENTITIES.with( |refcell|{ 
            let pidentities = &*refcell.borrow();
            pidentities.pidentities.keys().cloned().collect()
            
        })
    }

    pub fn get_derived_identity (key_name:String) -> Option<PIdentity> {
        
        PIDENTITIES.with( |refcell|{ 
            let pidentities = &*refcell.borrow();
            let pid = pidentities.pidentities.get(&key_name);
            match  pid {
                Some(pid) => {
                    let clone_pid = pid.clone();
                    Some(clone_pid)
                },
                None => None,
            }
        })
    }
}


#[derive(Debug, Default, Clone)]

pub struct PIdentity {
    key_name: String,
    created_ts: u64,
    public_key: Vec<u8>,
    chain_code: Vec<u8>,
}

impl PIdentity {
    pub fn get_key_name (&self) -> String {
        self.key_name.clone()
    }
    pub fn _get_created_ts(&self) -> u64 {
        self.created_ts
    }

    fn _get_public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
    fn _get_chain_code(&self) -> Vec<u8> {
        self.chain_code.clone()
    }
}


impl PIdentity {    

    pub async fn new_derived_identity(key_name:String) -> Self {

        let cloned_key_name= key_name.clone();
        let cloned_key_name2= key_name.clone();
        

        let created_ts = ic_cdk::api::time();

        let key_id = EcdsaKeyId {
            curve: ic_cdk::api::management_canister::ecdsa::EcdsaCurve::Secp256k1,
            name: String::from(PIdentities::get_environment().key_name),
        };



        let canister_id = Some(id());
        let derivation_path = vec![key_name.into_bytes()];


        let arg = EcdsaPublicKeyArgument { 
            canister_id, 
            derivation_path, 
            key_id
        };

        let r =  ecdsa_public_key(arg).await.expect("some error");


        
        let public_key = r.0.public_key;
        let chain_code = r.0.chain_code;

        let new_identity = Self { key_name: cloned_key_name, created_ts, public_key, chain_code};
        let cloned_new_identity = new_identity.clone();


        PIDENTITIES.with(move |refcell|{
            let pidentities = &mut *refcell.borrow_mut();

            (*pidentities).pidentities.insert(cloned_key_name2, new_identity);
            cloned_new_identity
        })        
    }
}












#[derive(Clone, Debug)]
enum MessageStatus {
    Created,
    Signed,
    _Sent,     
}


#[derive(Debug, Default)]
struct Messages {
    messages:RefCell<BTreeMap<String, Message>>,
}


#[derive(Clone, Debug)]
struct Message {

    uuid: String,
    created_ts: u64,
    last_updated_ts: u64,
    status: MessageStatus,

    original_message: String,
    hashed_message: Vec<u8>,
    signed_by: String,
    signature: Vec<u8>,

}


fn hash_message(original_message:&str) -> Vec<u8> {
    let mut s = Sha256::new();
    s.update(original_message.as_bytes());
    let r = s.finalize();
    let hashed_message = r.to_vec();
    hashed_message
}



impl Message {


    fn new(original_message: &str, signed_by:&str, uuid: (Vec<u8>, )) -> Option<Self> {

        
        let uuid= uuid.0;
        let uuid = HEXUPPER.encode(&uuid);
        let cloned_uuid = uuid.clone();

            
        MESSAGES.with(move |refcell| {

            let created_ts = ic_cdk::api::time();

            let hashed_message = hash_message(original_message);

            let a = Self { 
                uuid,
                created_ts,
                last_updated_ts: created_ts,
                status: MessageStatus::Created,

                original_message: String::from(original_message),
                hashed_message,
                signed_by: signed_by.to_owned(),
                signature: vec![],

            };
            let cloned_a = a.clone();
            let  messages = &mut *refcell.borrow_mut();

            let x = &mut *messages.messages.borrow_mut();

            x.insert(cloned_uuid, a);
            

            Some(cloned_a)
        })
    }        
}


impl Message {
    pub fn get_uuid(&self) -> &str {
        &self.uuid
    }

    pub fn get_created_ts(&self) -> u64 {
        self.created_ts
    }
    pub fn set_status(&mut self, status:MessageStatus) {
        self.status = status;

    }

    pub fn set_last_updated_ts (&mut self, last_updated_ts:u64)  {
        self.last_updated_ts = last_updated_ts;
    }

    pub fn set_signature(&mut self, signature: Vec<u8>) {
        self.signature = signature;

    }
}


