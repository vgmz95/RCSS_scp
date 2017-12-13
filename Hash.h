#ifndef HASH_H
#define HASH_H
#include <string>
#include <cryptopp/sha.h>
#include <cryptopp/secblock.h>

class Hash {
public:
    Hash(unsigned int);
    virtual ~Hash();
    void calculaHash(std::string K_nombre_archivo, std::string C_nombre_archivo);
    std::vector <std::string> shareECC(unsigned int umbral, unsigned int numero_shares, std::string nombre_archivo);
    void recoverECC(unsigned int umbral, std::vector<std::string> S_nombre_fragmentos_ECC);

    bool operator==(const Hash& right) const {
        return this->H_data_string == right.H_data_string;
    }

private:
    CryptoPP::SHA256 sha256;
    std::string H_data_string;
    unsigned int indice;
    void acumulaHashArchivo(CryptoPP::SHA256 &sha256, std::string nombre_archivo);

};

#endif /* HASH_H */

