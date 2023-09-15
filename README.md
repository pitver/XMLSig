# Getting Started
## данный пример для ГИИС ДМДК


### generate JKS
Выполнить команду(использовать keytool для java 11 )
keytool -genkeypair -alias test-cert -keyalg RSA -keysize 2048 -storetype JKS 
keytool -importkeystore -srckeystore "C:\Users\tibco_admin\Desktop\testuser2018_gost2012.pfx" -srcstoretype pkcs12 -destkeystore "C:\Users\tibco_admin\Desktop\clientcert.jks" -deststoretype JKS




