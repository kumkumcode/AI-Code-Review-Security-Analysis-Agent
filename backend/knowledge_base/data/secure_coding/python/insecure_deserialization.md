## Shelve

The shelve module is based on pickle.

It is unsafe for untrusted data because it can perform insecure deserialization.

Avoid using shelve with data from unknown sources.


## Multiprocessing

The multiprocessing Connection.recv() method uses pickle internally.

Receiving untrusted data can lead to security risks.

Always validate and trust the data source before processing.

## Shelve

The shelve module stores Python objects using pickle internally.

Because it uses pickle, loading a shelf from an untrusted source is unsafe.

An attacker can create malicious data that may execute arbitrary code during loading.

### Prevention

- Do not load shelve files from unknown or untrusted sources.
- Validate the source of stored data before loading.
- Use safer formats like JSON when working with external data.