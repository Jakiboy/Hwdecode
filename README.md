# Hwdecode

Decode and decrypt PPP (Point-to-Point Protocol) passwords encoded by HUAWEI routers. This tool takes an encrypted password string (typically starting with $2$ and ending with $) and decrypts it using a predefined AES decryption algorithm. It is particularly useful for recovering plaintext passwords from configurations exported from HUAWEI routers used by many ISPs.

**- This script decode all encoded data including root password -** 

## Installing

```bash
pip install -r requirements.txt
```

## Usage

```bash
python Hwdecode.py 'HEX'
python Hwdecode.py --file config.xml
```

## Teseted:

* **Huawei DG8245V-10** ^1.x

## Resources

* [Huawei configuration file password encryption](https://blog.fayaru.me/posts/huawei_router_config/)
* [AESCrypt2](https://github.com/palmerc/AESCrypt2)
