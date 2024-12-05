# CS181 Project 2: Security
In this project, I implemented a security layer on top of the reliability layer from Project 1. In doing so, I utilized cryptographic techniques such as elliptic curve cryptography, Type-Length-Value (TLV) format, Diffie-Hellman, authentication via HMAC SHA-256, and encryption via AES-256-CBC with PKCS #7 padding. 

Since there would be alot of TLV parsing and creation, I chose to create a separate file, `tlv.c`, for the purpose of interacting with them. 