# CS 344 OTP

####Five small C programs that encrypt and decrypt information using a one-time pad-like system.

Two of these will function like “daemons” (but aren't actually daemons), and will be accessed using network sockets. Two will use the daemons to perform work, and the last is a standalone utility.

**otp_enc_d**: This program will run in the background as a daemon. Its function is to perform the actual encoding, as descripted above in the Wikipedia quote. This program will listen on a particular port, assigned when it is first ran, and receives plaintext and a key via that port when a connection to it is made. It will then write back the ciphertext to the process that it is connected to via the same port. Note that the key passed in must be at least as big as the plaintext. This program must output an error if the program cannot be run due to a network error, such as the ports being unavailable.

When otp_enc_d makes a connection with otp_enc, it forks off a separate process immediately, and is available to receive more connections. It can support up to five concurrent socket connections. In the forked off process, the actual encryption will take place, and the ciphertext will be written back.

>otp_enc_d *listening_port*

listening_port is the port that otp_enc_d should listen on. You will always start otp_enc_d in the background.

>$ otp_enc_d 57171 &

**otp_enc**: This program connects to otp_enc_d, and asks it to perform a one-time pad style encryption as detailed above. By itself, otp_enc doesn’t do the encryption. Its syntax is as follows:

> otp_enc *plaintext key port*

  In this syntax, plaintext is the name of a file in the current directory that contains the plaintext you wish to encrypt. Similarly, key contains the encryption key you wish to use to encrypt the text. Finally, port is the port that otp_enc should attempt to connect to otp_enc_d on.

When otp_enc receives the ciphertext, it should output it to stdout. Thus, otp_enc can be launched in any of the following methods, and should send its output appropriately:
>$ otp_enc myplaintext mykey 57171
>$ otp_enc myplaintext mykey 57171 > myciphertext
>$ otp_enc myplaintext mykey 57171 > myciphertext &

**otp_dec_d**: This program performs exactly like otp_enc_d, in syntax and usage. In this case, however, otp_dec_d will decrypt ciphertext it is given, using the passed-in ciphertext and key. Thus, it returns plaintext again to otp_dec. 

**otp_dec**: Similarly, this program will connect to otp_dec_d and will ask it to decrypt ciphertext using a passed-in ciphertext and key. It will use the same syntax and usage as otp_enc,

**keygen**: This program creates a key file of specified length. The characters in the file generated will be any of the 27 allowed characters, generated using the standard UNIX randomization methods.

The syntax for keygen is as follows:
>keygen *keylength* > mykey

Example command line:

>$ cat plaintext1

>THE RED GOOSE FLIES AT MIDNIGHT

>$ otp_enc_d 57171 &

>$ otp_dec_d 57172 &

>$ keygen 1024 > mykey

>$ otp_enc plaintext1 mykey 57171 > ciphertext1

>$ cat ciphertext1

>GU WIRGEWOMGRIFOENBYIWUG T WOFL

>$ otp_dec ciphertext1 mykey 57172 > plaintext1_a

>$ cat plaintext1_a

>THE RED GOOSE FLIES AT MIDNIGHT

>$ cmp plaintext1 plaintext1_a

>$ echo $?

>0
