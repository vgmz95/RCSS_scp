#include "Hash.h"
#include <string>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <cryptopp/sha.h>
#include <cryptopp/ida.h>
#include <cryptopp/files.h> //
#include "ezpwd/rs"


Hash::Hash(unsigned int indice) {
    this->H_data_string = "";
    this->indice = indice;
}

Hash::~Hash() {
    this->H_data_string.clear();
    this->sha256.Restart();
}

void Hash::calculaHash(std::string K_nombre_archivo, std::string C_nombre_archivo) {
    CryptoPP::SecByteBlock H_data(NULL, CryptoPP::SHA256::DIGESTSIZE);
    sha256.Restart();
    acumulaHashArchivo(sha256, K_nombre_archivo); //K
    acumulaHashArchivo(sha256, C_nombre_archivo); //C
    sha256.Final(H_data);
    CryptoPP::ArraySource as(H_data, H_data.size(), true,
            new CryptoPP::StringSink(H_data_string)
            );
}

void Hash::acumulaHashArchivo(CryptoPP::SHA256 &sha256, std::string nombre_archivo) {
    CryptoPP::SecByteBlock buffer(NULL, BUFSIZ);
    std::FILE* f = std::fopen(nombre_archivo.c_str(), "r");
    int leido = 0;
    do {
        std::memset(buffer.data(), '\0', buffer.size());
        leido = std::fread(buffer.data(), sizeof (byte), buffer.size(), f);
        sha256.Update(buffer.data(), leido);
    } while (leido != 0);
    std::fclose(f);
}

std::vector <std::string> Hash::shareECC(unsigned int umbral, unsigned int numero_shares, std::string nombre_archivo) {
    std::vector<std::string> S_nombre_fragmentos_ECC;

    CryptoPP::ChannelSwitch *channelSwitch = NULL;
    CryptoPP::StringSource source(H_data_string, false,
            new CryptoPP::InformationDispersal(umbral, numero_shares,
            channelSwitch = new CryptoPP::ChannelSwitch
            )
            );


    CryptoPP::vector_member_ptrs<CryptoPP::StringSink> stringSinks(numero_shares);
    std::vector <std::string> S_data(numero_shares);
    std::string channel = "";
    for (unsigned int i = 0; i < numero_shares; i++) {
        stringSinks[i].reset(new CryptoPP::StringSink(S_data[i]));
        channel = CryptoPP::WordToString<CryptoPP::word32>(i);
        stringSinks[i]->Put((const byte *) channel.data(), 4);
        channelSwitch->AddRoute(channel, *stringSinks[i], CryptoPP::DEFAULT_CHANNEL);
    }
    source.PumpAll();


    std::string nombre_archivo_temp;
    std::string indice_str;
    std::string i_str;
    std::stringstream str_stream;
    for (unsigned int i = 0; i < S_data.size(); i++) {
        ezpwd::RS < 255, 255 - 64 > rs; //Reed-Solomon, 64 simbolos de paridad
        rs.encode(S_data[i]);

        str_stream << std::setw(3) << std::setfill('0') << i;
        i_str = str_stream.str();
        str_stream.str("");
        str_stream.clear();
        str_stream << std::setw(3) << std::setfill('0') << indice;
        indice_str = str_stream.str();
        str_stream.str("");
        str_stream.clear();
        nombre_archivo_temp = nombre_archivo + ".S." + indice_str + '.' + i_str;
        CryptoPP::StringSource ss(S_data[i], true,
                new CryptoPP::FileSink(nombre_archivo_temp.c_str(), true)
                );
        S_nombre_fragmentos_ECC.push_back(nombre_archivo_temp);
        indice_str.clear();
        i_str.clear();
        nombre_archivo_temp.clear();
    }
    return S_nombre_fragmentos_ECC;

}

void Hash::recoverECC(unsigned int umbral, std::vector<std::string> S_nombre_fragmentos_ECC) {
    std::vector<std::string> S_data;
    //Leyendo la informacion desde los archivos de fragmentos
    for (unsigned int i = 0; i < S_nombre_fragmentos_ECC.size(); i++) {
        std::string S_data_temp = "";
        CryptoPP::FileSource fs(S_nombre_fragmentos_ECC[i].c_str(), true,
                new CryptoPP::StringSink(S_data_temp),
                true);
        S_data.push_back(S_data_temp);
        S_data_temp.clear();
    }

    //Recuperando la informacion de paridad
    std::vector<std::string> S_data_recuperado;
    for (unsigned int i = 0; i < S_data.size(); i++) {
        ezpwd::RS < 255, 255 - 64 > rs; //64 simbolos de paridad
        int resultado = rs.decode(S_data[i]);
        if (resultado >= 0) {
            std::cout << "Se recuperó " << S_nombre_fragmentos_ECC[i] << " con " << resultado << "  errores" << std::endl;
            S_data_recuperado.push_back(S_data[i].substr(0, S_data[i].length() - rs.nroots()));
        } else {
            std::cout << "El archivo " << S_nombre_fragmentos_ECC[i] << " no se pudo recuperar" << std::endl;
        }
    }

    if (S_data_recuperado.size() < umbral) {
        H_data_string = "";
        return;
    }

    CryptoPP::InformationRecovery recovery(umbral, new CryptoPP::StringSink(H_data_string));
    CryptoPP::vector_member_ptrs<CryptoPP::StringSource> stringSources(umbral);
    CryptoPP::SecByteBlock channel(4);
    unsigned int i;
    for (i = 0; i < umbral; i++) {
        //std::cout << std::to_string(i) << std::endl;
        stringSources[i].reset(new CryptoPP::StringSource(S_data_recuperado[i], false));
        stringSources[i]->Pump(4);
        stringSources[i]->Get(channel, 4);
        stringSources[i]->Attach(new CryptoPP::ChannelSwitch(recovery, std::string((char *) channel.begin(), 4)));
    }

    while (stringSources[0]->Pump(256))
        for (i = 1; i < umbral; i++)
            stringSources[i]->Pump(256);

    for (i = 0; i < umbral; i++)
        stringSources[i]->PumpAll();

}
