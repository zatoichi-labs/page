use age;
use secrecy::Secret;
use std::io::{Read, Write};
use std::str::FromStr;

use pyo3::prelude::*;
use pyo3::types::PyAny;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;
use pyo3::create_exception;
use pyo3::exceptions::Exception;

create_exception!(page, PageUsageError, Exception);

#[pyclass]
pub struct Identity {
    secret: String,
    pub keys: Vec<age::keys::Identity>,
}

impl<'p> FromPyObject<'p> for Identity {
    fn extract(obj: &'p PyAny) -> PyResult<Self> {
        let result: &Self = obj.downcast_ref()?;
        Ok(Self {
            secret: result.secret.clone(),
            keys: age::keys::Identity::from_buffer(result.secret.as_bytes())
                .map_err(|_e| PageUsageError::py_err("Could not parse keys from secret!"))?,
        })
    }
}

#[pymethods]
impl Identity {

    #[new]
    pub fn new(obj: &PyRawObject, secret: String) -> PyResult<()> {
        obj.init(Self::from_secret(secret)?);
        Ok(())
    }

    #[staticmethod]
    pub fn from_secret(secret: String) -> PyResult<Self> {
        let keys = age::keys::Identity::from_buffer(secret.as_bytes())
            .map_err(|_e| PageUsageError::py_err("Could not parse keys from secret!"))?;
        Ok(Self {
            secret,
            keys,
        })
    }

    #[staticmethod]
    pub fn from_file(filename: String) -> PyResult<Self> {
        let keys = age::keys::Identity::from_file(filename)
            .map_err(|_e| PageUsageError::py_err("Could not parse keys from secret!"))?;
        Ok(Self {
            secret: String::new(),
            keys,
        })
    }

    #[staticmethod]
    pub fn generate() -> PyResult<Self> {
        let secret = age::SecretKey::generate().to_str();
        let keys = age::keys::Identity::from_buffer(secret.as_bytes())
            .map_err(|_e| PageUsageError::py_err("Could not parse keys from secret!"))?;
        Ok(Self {
            secret,
            keys,
        })
    }

    pub fn public(&self) -> Vec<String> {
        self.keys.iter().map(|id| {
            match id.key() {
                age::keys::IdentityKey::Unencrypted(key) =>
                    Some(key.to_public().to_str()),
                _ => None,
            }
        })
        .filter(|key| key.is_some())
        .map(|key| key.unwrap())
        .collect()
    }
}

#[pyfunction]
pub fn encrypt<'p>(py: Python<'p>,
                   message: &[u8],
                   public_keys: Option<Vec<String>>,
                   passphrase: Option<String>,
) -> PyResult<&'p PyBytes> {
    let encryptor = match (public_keys, passphrase) {
        (Some(keys), None) => {
            let keys: Result<Vec<age::keys::RecipientKey>, _> = keys.iter()
                .map(|k| age::keys::RecipientKey::from_str(&k))
                .collect();
            let keys = keys
                .map_err(|_e| PageUsageError::py_err("Could not parse keys from string!"))?;
            age::Encryptor::Keys(keys)
        },
        (None, Some(passphrase)) =>
            age::Encryptor::Passphrase(Secret::new(passphrase)),
        _ => return Err(
            PageUsageError::py_err(
                "Must specify keyword arg of: passphrase or public_keys (but not both)"
            )
        ),
    };
    let mut encrypted = vec![];
    {
        let mut writer = encryptor.wrap_output(&mut encrypted, false)?;
        writer.write_all(message)?;
        writer.finish()?;
    };
    Ok(PyBytes::new(py, encrypted.as_slice()))
}

#[pyfunction]
pub fn decrypt<'p>(py: Python<'p>,
                   message: &[u8],
                   private_keys: Option<Vec<Identity>>,
                   passphrase: Option<String>,
) -> PyResult<&'p PyBytes> {
    let decryptor = match (private_keys, passphrase) {
        (Some(keys), None) => {
            let keys: Vec<age::keys::Identity> = keys.iter()
                .flat_map(|k| {
                    age::keys::Identity::from_buffer(k.secret.as_bytes())
                        .expect("This is safe because we have already parsed secret")
                })
                .collect();
            age::Decryptor::Keys(keys)
        },
        (None, Some(passphrase)) =>
            age::Decryptor::Passphrase(Secret::new(passphrase)),
        _ => return Err(
            PageUsageError::py_err(
                "Must specify keyword arg of: passphrase or private_keys (but not both)"
            )
        ),
    };
    let mut reader = decryptor.trial_decrypt(message, |_| None)
        .map_err(|_e| PageUsageError::py_err("Decryption didn't work!"))?;
    let mut decrypted = vec![];
    reader.read_to_end(&mut decrypted)
        .map_err(|_e| PageUsageError::py_err("Reading didn't work!"))?;
    Ok(PyBytes::new(py, decrypted.as_slice()))
}

#[pymodule]
fn page(py: Python, module: &PyModule) -> PyResult<()> {
    module.add("PageUsageError", py.get_type::<PageUsageError>())?;
    module.add_wrapped(wrap_pyfunction!(encrypt))?;
    module.add_wrapped(wrap_pyfunction!(decrypt))?;
    module.add_class::<Identity>()?;
    Ok(())
}
