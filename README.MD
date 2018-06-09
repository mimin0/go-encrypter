Command line tool for encrypt/decrypt value that can be used for make more secure launch application (e.g application inside containers)

encryption usage:

    $ go build . && ./go-encrypter -encrypt=super_secret_password
    --encryption--
    Jli_aTUaP1IkIowWOeyCpLk3awXV_Nhf9wecb7SbjfM_DoZ72Q==

decryption usage:

    $ go build . && ./go-encrypter -decrypt=Jli_aTUaP1IkIowWOeyCpLk3awXV_Nhf9wecb7SbjfM_DoZ72Q==
    --decryption--
    super_secret_password
