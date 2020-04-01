use age;
use secrecy::{ExposeSecret, Secret};
use std::io::{Read, Write};
use std::str::FromStr;

use pyo3::create_exception;
use pyo3::exceptions::Exception;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;

create_exception!(page, PageUsageError, Exception);

#[pyclass]
pub struct Identity {
    secret: String,
    pub keys: Vec<age::keys::Identity>,
}

impl<'p> FromPyObject<'p> for Identity {
    fn extract(obj: &'p PyAny) -> PyResult<Self> {
        let result: PyRef<Self> = obj.extract()?;
        Self::new(result.secret.clone())
    }
}

#[pymethods]
impl Identity {
    #[new]
    pub fn new(secret: String) -> PyResult<Self> {
        Self::from_secret(secret)
    }

    #[staticmethod]
    pub fn from_secret(secret: String) -> PyResult<Self> {
        let keys = age::keys::Identity::from_buffer(secret.as_bytes())
            .map_err(|_e| PageUsageError::py_err("Could not parse keys from secret!"))?;
        Ok(Self { secret, keys })
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
        let secret = age::SecretKey::generate()
            .to_string()
            .expose_secret()
            .to_owned();
        let keys = age::keys::Identity::from_buffer(secret.as_bytes())
            .map_err(|_e| PageUsageError::py_err("Could not parse keys from secret!"))?;
        Ok(Self { secret, keys })
    }

    pub fn public(&self) -> Vec<String> {
        self.keys
            .iter()
            .map(|id| match id.key() {
                age::keys::IdentityKey::Unencrypted(key) => Some(key.to_public().to_string()),
                _ => None,
            })
            .filter(|key| key.is_some())
            .map(|key| key.unwrap())
            .collect()
    }
}

#[pyfunction]
pub fn encrypt<'p>(
    py: Python<'p>,
    message: &[u8],
    public_keys: Option<Vec<String>>,
    passphrase: Option<String>,
) -> PyResult<&'p PyBytes> {
    let encryptor = match (public_keys, passphrase) {
        (Some(keys), None) => {
            let keys: Result<Vec<age::keys::RecipientKey>, _> = keys
                .iter()
                .map(|k| age::keys::RecipientKey::from_str(&k))
                .collect();
            let keys =
                keys.map_err(|_e| PageUsageError::py_err("Could not parse keys from string!"))?;
            age::Encryptor::with_recipients(keys)
        }
        (None, Some(passphrase)) => age::Encryptor::with_user_passphrase(Secret::new(passphrase)),
        _ => {
            return Err(PageUsageError::py_err(
                "Must specify keyword arg of: passphrase or public_keys (but not both)",
            ))
        }
    };
    let mut encrypted = vec![];
    {
        let mut writer = encryptor.wrap_output(&mut encrypted, age::Format::Binary)?;
        writer.write_all(message)?;
        writer.finish()?;
    };
    Ok(PyBytes::new(py, encrypted.as_slice()))
}

#[pyfunction]
pub fn decrypt<'p>(
    py: Python<'p>,
    message: &[u8],
    private_keys: Option<Vec<Identity>>,
    passphrase: Option<String>,
) -> PyResult<&'p PyBytes> {
    let decryptor = age::Decryptor::new(message).unwrap();
    let mut reader = match (decryptor, private_keys, passphrase) {
        (age::Decryptor::Recipients(d), Some(keys), None) => {
            let keys: Vec<age::keys::Identity> = keys
                .iter()
                .flat_map(|k| {
                    age::keys::Identity::from_buffer(k.secret.as_bytes())
                        .expect("This is safe because we have already parsed secret")
                })
                .collect();
            d.decrypt(keys.as_slice())
        }
        (age::Decryptor::Passphrase(d), None, Some(passphrase)) => {
            d.decrypt(&Secret::new(passphrase), None)
        }
        (_, None, None) | (_, Some(_), Some(_)) => {
            return Err(PageUsageError::py_err(
                "Must specify keyword arg of: passphrase or private_keys (but not both)",
            ))
        }
        _ => {
            return Err(PageUsageError::py_err(
                "Mismatch between encryption type and supplied decryption key or passphrase",
            ))
        }
    }
    .map_err(|_e| PageUsageError::py_err("Decryption didn't work!"))?;
    let mut decrypted = vec![];
    reader
        .read_to_end(&mut decrypted)
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
