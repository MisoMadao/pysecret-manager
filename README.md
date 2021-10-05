# pysecret_manager

Very simple python module to manage secrets

## requirements

[criptography](https://cryptography.io/en/latest/)

## usage

### as module

``` python
>>> from secret_manager import SecretManager
>>> from getpass import getpass
>>> with SecretManager(getpass('master key: ')) as sm:
...     sm.add_secret('test')
... 
master key: 
secret value: 
>>> 
>>> with SecretManager(getpass('master key: ')) as sm:
...     sm.get_secret('test')
... 
master key: 
'secretvalue'
>>> 
>>> with SecretManager(getpass('master key: ')) as sm:
...     sm.del_secret('test')
... 
master key: 
>>>
```

### command line

``` bash
(pysecret-manager) $ ./secret_manager.py -n test add
master key: 
secret value: 
INFO:root:secret succesfully added
(pysecret-manager) $ ./secret_manager.py -n test get
master key: 
secretvalue
(pysecret-manager) $ ./secret_manager.py getall
master key: 
test
(pysecret-manager) $ ./secret_manager.py -n test del
master key: 
INFO:root:secret successfully deleted
(pysecret-manager) $ ./secret_manager.py -n test add
master key: 
ERROR:root:error in decryption
```