# Task 4: File Protection Utility

```bash
printf 'confidential note\n' > note.txt
python3 file_protection.py encrypt note.txt note.bin 'demo-password'
python3 file_protection.py decrypt note.bin restored.txt 'demo-password'
```

This is an educational standard-library implementation with password-based key derivation and integrity checking. For production, use an audited AEAD library such as `cryptography` Fernet or AES-GCM.
