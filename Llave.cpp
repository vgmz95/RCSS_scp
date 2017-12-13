#include "Llave.h"
#include <string>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cryptopp/osrng.h>
#include <cryptopp/ida.h>//IDA y Shamir
#include <cryptopp/files.h> //Archivos

Llave::Llave(std::string nombre_archivo) {
    this->llave_data = CryptoPP::SecByteBlock(NULL, CryptoPP::AES::DEFAULT_KEYLENGTH);
    this->llave_data_string = "";
    this->llave_nombre_archivo = nombre_archivo += ".K";
    CryptoPP::SecByteBlock entropy = generaEntropia(); //Inicializacion de la semilla (entropia)
    this->drbg = new CryptoPP::Hash_DRBG < CryptoPP::SHA256, 128 / 8, 440 / 8 > (entropy, 32, entropy + 32, 16); //Generador NIST Hash_DRBG, tiene como semilla la entropia generada anteriormente
}

Llave::Llave(std::string nombre_archivo, std::vector <std::string> nombres_fragmentos_PSS) {
    this->llave_data = CryptoPP::SecByteBlock(NULL, CryptoPP::AES::DEFAULT_KEYLENGTH);
    this->llave_data_string = "";
    this->llave_nombre_archivo = nombre_archivo += ".K";
    CryptoPP::SecByteBlock entropy = generaEntropia(); //Inicializacion de la semilla (entropia)
    this->drbg = new CryptoPP::Hash_DRBG < CryptoPP::SHA256, 128 / 8, 440 / 8 > (entropy, 32, entropy + 32, 16); //Generador NIST Hash_DRBG, tiene como semilla la entropia generada anteriormente
    this->nombres_fragmentos_PSS = nombres_fragmentos_PSS;
}

Llave::~Llave() {
    delete drbg;
    this->llave_data_string.clear();
    this->llave_nombre_archivo.clear();
    this->nombres_fragmentos_PSS.clear();
}

CryptoPP::SecByteBlock Llave::obtieneLlave() {
    return llave_data;
}

CryptoPP::SecByteBlock Llave::generaEntropia() {//Función que se manda a llamar cada vez que se necesita añadir entropia al generador del NIST
    CryptoPP::SecByteBlock entropy(NULL, 48); //Bloque donde se almacena la entropia
    OS_GenerateRandomBlock(false, entropy, entropy.size());
    return entropy;
}

void Llave::generar() {//Función que genera una llave aleatoria para el cifrador AES
    drbg->GenerateBlock(llave_data, llave_data.size()); //Se genera una llave aleatoria
    llave_data_string.clear();
    CryptoPP::ArraySource(llave_data, llave_data.size(), true,
            new CryptoPP::StringSink(llave_data_string)
            );
}

std::vector <std::string> Llave::sharePSS(unsigned int umbral, unsigned int numero_shares) {
    if (numero_shares < 1 || numero_shares > 1000)
        throw CryptoPP::InvalidArgument("SecretShareFile: " + CryptoPP::IntToString(numero_shares) + " is not in range [1, 1000]");
    
    nombres_fragmentos_PSS.reserve(numero_shares);
    CryptoPP::ChannelSwitch *channelSwitch = NULL;
    CryptoPP::StringSource source(llave_data_string, false,
            new CryptoPP::SecretSharing(*drbg, umbral, numero_shares,
            channelSwitch = new CryptoPP::ChannelSwitch)
            );

    CryptoPP::vector_member_ptrs<CryptoPP::FileSink> fileSinks(numero_shares);
    std::string channel;

    std::string extension;
    std::string llave_nombre_archivo_tmp;
    std::stringstream str_stream;
    for (unsigned int i = 0; i < numero_shares; i++) {
        str_stream << std::setw(3) << std::setfill('0') << i; //Genera la cadena 000,001,002
        extension = '.' + str_stream.str();
        llave_nombre_archivo_tmp = llave_nombre_archivo + extension;
        fileSinks[i].reset(new CryptoPP::FileSink(llave_nombre_archivo_tmp.c_str()));
        nombres_fragmentos_PSS.push_back(llave_nombre_archivo_tmp); //Se añade el nombre archivo al vector
        channel = CryptoPP::WordToString<CryptoPP::word32>(i);
        fileSinks[i]->Put((const byte *) channel.data(), 4);
        channelSwitch->AddRoute(channel, *fileSinks[i], CryptoPP::DEFAULT_CHANNEL);
        extension.clear();
        str_stream.str("");
        str_stream.clear();
    }
    source.PumpAll();
    return nombres_fragmentos_PSS;
}

void Llave::recoverPSS(unsigned int umbral, unsigned int numero_shares) {
    if (umbral < 1 || umbral > 1000)
        throw CryptoPP::InvalidArgument("SecretRecoverFile: " + CryptoPP::IntToString(umbral) + " is not in range [1, 1000]");

    CryptoPP::SecretRecovery recovery(umbral,
            new CryptoPP::ArraySink(llave_data, llave_data.size())
            );

    CryptoPP::vector_member_ptrs<CryptoPP::FileSource> fileSources(umbral);
    CryptoPP::SecByteBlock channel(4);
    unsigned int i;
    for (i = 0; i < umbral; i++) {
        fileSources[i].reset(new CryptoPP::FileSource(nombres_fragmentos_PSS[i].c_str(), false));
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
