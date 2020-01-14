use age;
use secrecy::Secret;
use std::io::{Read, Write};
use std::str::FromStr;

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;
use pyo3::create_exception;
use pyo3::exceptions::Exception;

create_exception!(page, PageUsageError, Exception);

#[pyfunction(module = "page")]
pub fn encrypt<'p>(py: Python<'p>,
                   message: &[u8],
                   public_keys: Option<Vec<String>>,
                   passphrase: Option<String>,
) -> PyResult<&'p PyBytes> {
    let encryptor = match (public_keys, passphrase) {
        (Some(raw_keys), None) => {
            let mut keys = vec![];
            for key in raw_keys {
                let key = age::keys::RecipientKey::from_str(&key)
                    .map_err(|_e| PageUsageError::py_err("Could not use public key!"))?;
                keys.push(key);
            };
            age::Encryptor::Keys(keys)
        },
        (None, Some(passphrase)) =>
            age::Encryptor::Passphrase(Secret::new(passphrase)),
        _ => return Err(
            PageUsageError::py_err(
                "Must specify keyword arg of: passphrase or public_key"
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

#[pyclass]
pub struct Identity {
    secret: String,
    keys: Vec<age::keys::Identity>,
}

impl Clone for Identity {
    fn clone(&self) -> Self {
        Self::from_secret(self.secret.clone()).unwrap()
    }
}

#[pymethods]
impl Identity {

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
    pub fn generate() -> PyResult<Self> {
        Self::from_secret(age::SecretKey::generate().to_str())
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

    pub fn decrypt<'p>(&self,
                       py: Python<'p>,
                       message: &[u8],
                       passphrase: Option<String>,
    ) -> PyResult<&'p PyBytes> {
        let decryptor = match passphrase {
            Some(passphrase) =>
                age::Decryptor::Passphrase(Secret::new(passphrase)),
            None => {
                age::Decryptor::Keys(self.clone().keys)
            },
        };
        let mut reader = decryptor.trial_decrypt(message, |_| None)
            .map_err(|_e| PageUsageError::py_err("Decryption didn't work!"))?;
        let mut decrypted = vec![];
        reader.read_to_end(&mut decrypted)
            .map_err(|_e| PageUsageError::py_err("Reading didn't work!"))?;
        Ok(PyBytes::new(py, decrypted.as_slice()))
    }
}

#[pymodule]
fn page(py: Python, module: &PyModule) -> PyResult<()> {
    module.add("PageUsageError", py.get_type::<PageUsageError>())?;
    module.add_wrapped(wrap_pyfunction!(encrypt)).unwrap();
    module.add_class::<Identity>()?;
    Ok(())
}
