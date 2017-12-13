#ifndef ARCHIVO_H_
#define ARCHIVO_H_
#include "Llave.h"
#include <string>
#include <cryptopp/secblock.h>

class Archivo {
public:
    Archivo(std::string nombre_archivo);
    Archivo(std::string nombre_archivo, std::vector <std::string> nombres_fragmentos_IDA);
    virtual ~Archivo();
    void cifrar(Llave &llave, CryptoPP::SecByteBlock iv);
    void descifrar(Llave &llave, CryptoPP::SecByteBlock iv);
    std::vector<std::string> shareIDA(unsigned int umbral, unsigned int numero_shares);
    void recoverIDA(unsigned int umbral, unsigned int numero_shares);
    std::vector<std::string> getNombresFragmentosIDA() const;
    std::string getNombreArchivoCifrado() const;
    std::string getNombreArchivo() const;
    void setNombresFragmentosIDA(std::vector<std::string> nombres_fragmentos_IDA);
    void setNombreArchivoCifrado(std::string nombre_archivo_cifrado);
    void setNombreArchivo(std::string nombre_archivo);
     
    
private:
    std::string nombre_archivo;
    std::string nombre_archivo_cifrado;
    std::vector <std::string> nombres_fragmentos_IDA;
};

#endif
