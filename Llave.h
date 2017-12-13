#ifndef LLAVE_H_
#define LLAVE_H_
#include <string>
#include <cryptopp/drbg.h> //Generadores NIST

class Llave {
public:
    Llave(std::string nombre_archivo);
    Llave(std::string nombre_archivo, std::vector <std::string> nombres_fragmentos_PSS);
    virtual ~Llave();
    void generar();
    CryptoPP::SecByteBlock obtieneLlave();
    std::vector <std::string> sharePSS(unsigned int umbral, unsigned int numeroShares);
    void recoverPSS(unsigned int umbral, unsigned int numeroShares);

private:
    CryptoPP::SecByteBlock llave_data;
    std::string llave_data_string;
    std::string llave_nombre_archivo;
    std::vector <std::string> nombres_fragmentos_PSS;
    CryptoPP::Hash_DRBG<CryptoPP::SHA256, 128 / 8, 440 / 8 > *drbg = NULL;
    CryptoPP::SecByteBlock generaEntropia();
};

#endif
