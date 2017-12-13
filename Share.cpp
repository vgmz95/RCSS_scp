#include "Archivo.h"
#include "Hash.h"
#include "Fragmento.h"

#include <cryptopp/aes.h>
#include <string>
#include <fstream>
#include <iostream>
#include <algorithm>

int main(int argc, char *argv[]) {
    //Vector de inicializacion IV  *Debe de ser público*
    CryptoPP::SecByteBlock iv(NULL, CryptoPP::AES::BLOCKSIZE); //NULL para inicializar en 0's
    std::string nombre_archivo = "", ubicacion_remota = "", servidor_remoto = "";
    std::string carpeta_destino = "";
    std::string nombre_archivo_servidores = "";
    unsigned int umbral;
    unsigned int numero_shares;

    try {//Parseo de argumentos
        if (argc != 8) {
            std::cout << "Uso: ./Share nombre_archivo ubicacion_remota servidor_remoto umbral numero_shares carpeta_destino archivo_servidores" << std::endl;
            return -1;
        }
        nombre_archivo = std::string(argv[1]); //Archivo
        ubicacion_remota = std::string(argv[2]);
        servidor_remoto = std::string(argv[3]);
        umbral = std::stoul(std::string(argv[4]));
        numero_shares = std::stoul(std::string(argv[5]));
        carpeta_destino = std::string(argv[6]);
        nombre_archivo_servidores = std::string(argv[7]);
        std::cout << "Archivo a procesar: " << nombre_archivo << " umbral: " << umbral << "," << numero_shares << std::endl;
    } catch (std::exception& e) {
        std::cerr << "Error al parsear los argumentos: " << e.what() << std::endl;
        return -1;
    }
    //Transfiere el archivo desde el servidor web a la máquina actual 
    std::string comando_recuperacion = "scp " + servidor_remoto + ":/" + ubicacion_remota + "/" + nombre_archivo + " ./";

    std::cout << "Comando transferencia:" << comando_recuperacion << std::endl;
    system(comando_recuperacion.c_str());

    Archivo archivo(nombre_archivo);
    Llave llave(nombre_archivo);
    llave.generar(); //Generación aleatoria de la llave
    archivo.cifrar(llave, iv); //Cifrado del archivo

    std::cout << "Share PSS..." << std::flush;
    std::vector <std::string> K = llave.sharePSS(umbral, numero_shares); //Share PSS de la llave
    std::cout << "OK" << std::endl;

    std::cout << "Share IDA..." << std::flush;
    std::vector <std::string> C = archivo.shareIDA(umbral, numero_shares); //Share IDA del archivo
    std::cout << "OK" << std::endl;

    std::cout << "Share ECC..." << std::flush;
    std::vector <std::vector < std::string>> S;
    S.reserve(numero_shares);
    for (unsigned int i = 0; i < numero_shares; i++) {
        Hash h = Hash(i);
        h.calculaHash(K[i], C[i]);
        S.push_back(h.shareECC(umbral, numero_shares, nombre_archivo));
    }
    std::cout << "OK" << std::endl;

    std::vector <Fragmento> fragmentos;
    fragmentos.reserve(numero_shares);
    std::cout << "\tInformación de los fragmentos" << std::endl;
    for (unsigned int i = 0; i < numero_shares; i++) {
        std::vector<std::string> S_temp;
        for (unsigned int j = 0; j < numero_shares; j++) {
            S_temp.push_back(S[j][i]);
        }
        Fragmento fragmento(K[i], C[i], S_temp, i);
        std::cout << fragmento << std::endl;
        fragmentos.push_back(fragmento);
    }

    //Lectura de servidores
    std::ifstream archivo_servidores(nombre_archivo_servidores.c_str());
    std::string servidor_str;
    std::vector <ServidorSsh> servidores;
    servidores.reserve(numero_shares);
    while (std::getline(archivo_servidores, servidor_str)) {
        std::cout << "Servidor: " << servidor_str << std::endl;
        servidores.push_back(ServidorSsh(servidor_str));
    }

    //Distribucion en los demas servidores
    for (unsigned int i = 0; i < fragmentos.size(); i++) {
        fragmentos[i].distribuir(servidores[i], carpeta_destino, nombre_archivo);
    }

    unsigned int numero_OK = std::count_if(fragmentos.begin(), fragmentos.end(), [](const Fragmento & fragmento) {
        return fragmento.isOk(); });

    //Borrando archivos intermedios     
    for (auto &fragmento : fragmentos) {
        fragmento.borra();
    }
    std::cout << "Se borraron correctamente los archivos locales" << std::endl;

    //Paso final
    if (numero_OK >= umbral) {
        std::cout << "Se distribuyeron correctamente todos los shares dentro del umbral" << std::endl;
        std::remove(nombre_archivo.c_str()); //Se borra el archivo original una vez terminado el proceso de share
        std::cout << "Se borró correctamente el archivo original" << std::endl;
        std::cout << "El archivo se compartio correctamente" << std::endl;
        return 0;
    } else {
        std::cout << "No se pudo distribuir el archivo dentro del umbral" << std::endl;
        std::remove(nombre_archivo.c_str());
        return -1;
    }
}

