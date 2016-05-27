# Opsview Python REST API client

https://github.com/pschmitt/python-opsview

## Installation

```bash
pip install opsview
```

## Usage

```python
from opsview import Opsview
o = Opsview(
    'opsview.example.com',
    verify_ssl=True,
    username='pschmitt',
    password='MySecretPassw0rd'
)
```

## License

GPL3
