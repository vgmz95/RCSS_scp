#include "Archivo.h"
#include "Llave.h" 
#include <cryptopp/files.h> //Escritura en archivos
#include <cryptopp/ida.h> //IDA y Shamir
#include <cryptopp/aes.h> //Cifrador por bloques AES
#include <cryptopp/ccm.h> //Modo de operación CBC

#include <string>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdio> //para borrar archivo (std::remove)

Archivo::Archivo(std::string nombre_archivo) {
    this->nombre_archivo = nombre_archivo;
    this->nombre_archivo_cifrado = nombre_archivo + ".C";
}

Archivo::Archivo(std::string nombre_archivo, std::vector <std::string> nombres_fragmentos_IDA) {
    this->nombre_archivo = nombre_archivo;
    this->nombre_archivo_cifrado = nombre_archivo + ".C";
    this->nombres_fragmentos_IDA = nombres_fragmentos_IDA;
}

Archivo::~Archivo() {
    this->nombre_archivo.clear();
    this->nombre_archivo_cifrado.clear();
    this->nombres_fragmentos_IDA.clear();
}

void Archivo::cifrar(Llave &llave, CryptoPP::SecByteBlock iv) {
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption cifrado; //Objeto para el cifrado usando AES modo CBC
    cifrado.SetKeyWithIV(llave.obtieneLlave(), llave.obtieneLlave().size(), iv); //Se asigna la llave y el IV
    CryptoPP::FileSource s(nombre_archivo.c_str(), true, //Se cifra el archivo
            new CryptoPP::StreamTransformationFilter(cifrado,
            new CryptoPP::FileSink(nombre_archivo_cifrado.c_str(), true)
            )
            );
}

void Archivo::descifrar(Llave &llave, CryptoPP::SecByteBlock iv) {
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption d;
    d.SetKeyWithIV(llave.obtieneLlave(), llave.obtieneLlave().size(), iv);
    CryptoPP::FileSource s(nombre_archivo_cifrado.c_str(), true,
            new CryptoPP::StreamTransformationFilter(d,
            new CryptoPP::FileSink(nombre_archivo.c_str(), true) /////*********************Nombre que se le asigna al archivo una vez recuperado en claro**************///////
            )
            );
    std::remove(nombre_archivo_cifrado.c_str()); //Borra el archivo cifrado C
}

std::vector<std::string> Archivo::shareIDA(unsigned int umbral, unsigned int numero_shares) {
    if (umbral < 1 || umbral > 1000)
        throw CryptoPP::InvalidArgument("InformationDisperseFile: " + CryptoPP::IntToString(numero_shares) + " is not in range [1, 1000]");
    nombres_fragmentos_IDA.reserve(numero_shares);
    CryptoPP::ChannelSwitch *channelSwitch = NULL;
    CryptoPP::FileSource source(nombre_archivo_cifrado.c_str(), false,
            new CryptoPP::InformationDispersal(umbral, numero_shares,
            channelSwitch = new CryptoPP::ChannelSwitch
            )
            );

    CryptoPP::vector_member_ptrs<CryptoPP::FileSink> fileSinks(numero_shares);
    std::string channel;

    std::string extension;
    std::string nombre_archivo_cifrado_tmp;
    std::stringstream str_stream;
    for (unsigned int i = 0; i < numero_shares; i++) {
        str_stream << std::setw(3) << std::setfill('0') << i; //Genera la cadena 000,001,002
        extension = '.' + str_stream.str();
        nombre_archivo_cifrado_tmp = nombre_archivo_cifrado + extension;
        fileSinks[i].reset(new CryptoPP::FileSink(nombre_archivo_cifrado_tmp.c_str()));
        nombres_fragmentos_IDA.push_back(nombre_archivo_cifrado_tmp); //Se añade el nombre archivo al vector
        channel = CryptoPP::WordToString<CryptoPP::word32>(i);
        fileSinks[i]->Put((const byte *) channel.data(), 4);
        channelSwitch->AddRoute(channel, *fileSinks[i], CryptoPP::DEFAULT_CHANNEL);
        extension.clear();
        str_stream.str("");
        str_stream.clear();
    }
    source.PumpAll();
    std::remove(nombre_archivo_cifrado.c_str()); //Se borra el archivo cifrado original, una ves que ya se crearon sus shares
    return nombres_fragmentos_IDA;
}

void Archivo::recoverIDA(unsigned int umbral, unsigned int numero_shares) {
    if (umbral < 1 || umbral > 1000)
        throw CryptoPP::InvalidArgument("InformationRecoverFile: " + CryptoPP::IntToString(umbral) + " is not in range [1, 1000]");
    CryptoPP::InformationRecovery recovery(umbral, new CryptoPP::FileSink(nombre_archivo_cifrado.c_str()));
    CryptoPP::vector_member_ptrs<CryptoPP::FileSource> fileSources(umbral);
    CryptoPP::SecByteBlock channel(4);
    unsigned int i;
    for (i = 0; i < umbral; i++) {
        fileSources[i].reset(new CryptoPP::FileSource(nombres_fragmentos_IDA[i].c_str(), false));
        fileSources[i]->Pump(4);
        fileSources[i]->Get(channel, 4);
        fileSources[i]->Attach(new CryptoPP::ChannelSwitch(recovery, std::string((char *) channel.begin(), 4)));
    }

    while (fileSources[0]->Pump(256))
        for (i = 1; i < umbral; i++)
            fileSources[i]->Pump(256);

    for (i = 0; i < umbral; i++)
        fileSources[i]->PumpAll();
}

std::vector<std::string> Archivo::getNombresFragmentosIDA() const {
    return nombres_fragmentos_IDA;
}

std::string Archivo::getNombreArchivoCifrado() const {
    return nombre_archivo_cifrado;
}

std::string Archivo::getNombreArchivo() const {
    return nombre_archivo;
}

void Archivo::setNombresFragmentosIDA(std::vector<std::string> nombres_fragmentos_IDA) {
    this->nombres_fragmentos_IDA = nombres_fragmentos_IDA;
}

void Archivo::setNombreArchivoCifrado(std::string nombre_archivo_cifrado) {
    this->nombre_archivo_cifrado = nombre_archivo_cifrado;
}

void Archivo::setNombreArchivo(std::string nombre_archivo) {
    this->nombre_archivo = nombre_archivo;
}
