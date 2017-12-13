#include "Archivo.h"
#include "Fragmento.h"
#include "Hash.h"
#include <cryptopp/aes.h>
#include <sstream>
#include <iomanip>
#include <string>
#include <fstream>
#include <iostream>

std::vector <std::string> generaNombresArchivos(std::string nombre_archivo, unsigned int numero_shares, std::string extension_intermedia) {
    std::vector <std::string> nombres;
    nombres.reserve(numero_shares);
    std::string extension;
    std::stringstream str_stream;
    std::string nombre_archivo_tmp;
    for (unsigned int i = 0; i < numero_shares; i++) {
        str_stream << std::setw(3) << std::setfill('0') << i; //Genera la cadena 000,001,002
        extension = "." + extension_intermedia + "." + str_stream.str();
        nombre_archivo_tmp = nombre_archivo + extension;
        nombres.push_back(nombre_archivo_tmp);
        str_stream.str("");
        str_stream.clear();
        extension.clear();
        nombre_archivo_tmp.clear();
    }
    return nombres;
}

std::vector <std::vector < std::string>> generaNombresArchivosECC(std::string nombre_archivo, unsigned int numero_shares, std::string extension_intermedia) {
    std::vector <std::vector < std::string>> nombres;
    std::vector < std::string> nombres_temp;
    std::stringstream str_stream;
    std::string nombre_archivo_tmp;
    for (unsigned int i = 0; i < numero_shares; i++) {
        for (unsigned int j = 0; j < numero_shares; j++) {
            str_stream << std::setw(3) << std::setfill('0') << j; //Genera la cadena 000,001,002
            nombre_archivo_tmp = nombre_archivo + "." + extension_intermedia + "." + str_stream.str();
            str_stream.str("");
            str_stream.clear();
            str_stream << std::setw(3) << std::setfill('0') << i;
            nombre_archivo_tmp += "." + str_stream.str();
            nombres_temp.push_back(nombre_archivo_tmp);
            str_stream.str("");
            str_stream.clear();
            nombre_archivo_tmp.clear();
        }
        nombres.push_back(nombres_temp);
        nombres_temp.clear();
    }
    return nombres;
}

std::vector < std::string> obtieneSCorrespondiente(int numero_fragmento, std::vector <std::vector < std::string>> S) {
    std::vector < std::string> S_correspondiente;
    for (unsigned int i = 0; i < S.size(); i++) {
        S_correspondiente.push_back(S[i][numero_fragmento]);
    }
    return S_correspondiente;
}

std::vector <std::string> remueveIndices(std::vector <std::string> arreglo, std::vector <int> indices_corruptos, std::vector <int> indices_perdidos) {
    indices_perdidos.insert(indices_perdidos.end(), indices_corruptos.begin(), indices_corruptos.end());
    std::sort(indices_perdidos.begin(), indices_perdidos.end());
    for (int i = indices_perdidos.size() - 1; i >= 0; i--) {
        arreglo.erase(arreglo.begin() + indices_perdidos[i]);
    }
    return arreglo;
}

int main(int argc, char *argv[]) {
    //Vector de inicializacion IV  *Debe de ser público*
    CryptoPP::SecByteBlock iv(NULL, CryptoPP::AES::BLOCKSIZE); //NULL para inicializar en 0's
    std::string nombre_archivo = "", ubicacion_remota = "", servidor_remoto = "";
    std::string carpeta_origen = "";
    std::string nombre_archivo_servidores = "";
    unsigned int umbral;
    unsigned int numero_shares;


    //Parseo de argumentos
    try {
        if (argc != 8) {
            std::cout << "Uso: ./Recover nombre_archivo ubicacion_remota servidor_remoto umbral numero_shares carpeta_destino archivo_servidores" << std::endl;
            return -1;
        }
        nombre_archivo = std::string(argv[1]); //Archivo
        ubicacion_remota = std::string(argv[2]);
        servidor_remoto = std::string(argv[3]);
        umbral = std::stoul(std::string(argv[4]));
        numero_shares = std::stoul(std::string(argv[5]));
        carpeta_origen = std::string(argv[6]);
        nombre_archivo_servidores = std::string(argv[7]);
        std::cout << "Archivo a procesar: " << nombre_archivo << " umbral: " << umbral << "," << numero_shares << std::endl;
    } catch (std::exception& e) {
        std::cerr << "Error al parsear los argumentos: " << e.what() << std::endl;
        return -1;
    }

    //Creacion de los nombres (referencias) 
    std::vector <std::string> K = generaNombresArchivos(nombre_archivo, numero_shares, std::string("K"));
    std::vector <std::string> C = generaNombresArchivos(nombre_archivo, numero_shares, std::string("C"));
    std::vector <std::vector < std::string>> S = generaNombresArchivosECC(nombre_archivo, numero_shares, std::string("S"));
    std::vector <Fragmento> fragmentos;
    std::cout << "\tFragmentos a obtener" << std::endl;
    for (unsigned int i = 0; i < numero_shares; i++) {
        Fragmento fragmento(K[i], C[i], S[i], i);
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

    //Recuperar fragmentos 
    for (unsigned int i = 0; i < fragmentos.size(); i++) {
        fragmentos[i].recuperar(servidores[i], carpeta_origen, nombre_archivo);
    }

    //Asignacion de los fragmentos que sí se lograron recuperar de los demás servidores
    std::vector <int> indices_recuperados;
    std::vector <int> indices_perdidos;

    S.clear();
    for (unsigned int i = 0; i < fragmentos.size(); i++) {
        if (fragmentos[i].isOk()) {
            indices_recuperados.push_back(i);
            S.push_back(fragmentos[i].getS());
            std::cout << "El fragmento " << fragmentos[i].getIndice() << " se obtuvo correctamente" << std::endl;
        } else {
            indices_perdidos.push_back(i);
            std::cout << "El fragmento " << fragmentos[i].getIndice() << " no pudo ser obtenido del servidor" << std::endl;
        }
    }

    //Paso 2-3 RCSS
    std::cout << "\tRecover ECC" << std::endl;
    std::vector <int> indices_corruptos;
    for (auto &indice : indices_recuperados) {
        std::cout << "\nProcesando índice " << indice << std::endl;
        std::vector <std::string > s_prima = obtieneSCorrespondiente(indice, S);
        Hash hash(indice);
        Hash hash_prima(indice);
        hash.calculaHash(K[indice], C[indice]);
        hash_prima.recoverECC(umbral, s_prima);
        if (hash == hash_prima) {
            std::cout << K[indice] << " y " << C[indice] << " están OK" << std::endl;
        } else {
            indices_corruptos.push_back(indice);
            std::cout << K[indice] << " y " << C[indice] << " están corruptos" << std::endl;
        }
    }


    //Eliminar de K y C los que no estan OK
    unsigned int numero_fragmentos_usables = indices_recuperados.size() - indices_corruptos.size();
    if (numero_fragmentos_usables < umbral) {
        std::cout << "El número de fragmentos corruptos/perdidos supera el umbral" << std::endl;
        std::ofstream ofs(nombre_archivo.c_str());
        ofs << "";
        ofs.close();
        return -1;
    } else if (indices_corruptos.size() > 0 || indices_perdidos.size() > 0) {
        std::cout << "Eliminando indices perdidos y corruptos..." << std::flush;
        K = remueveIndices(K, indices_corruptos, indices_perdidos);
        C = remueveIndices(C, indices_corruptos, indices_perdidos);
        std::cout << "OK" << std::endl;
    }

    //Paso 4,5,6 RCSS    
    Archivo archivo(nombre_archivo, C);
    Llave llave(nombre_archivo, K);
    std::cout << "Recover PSS..." << std::flush;
    llave.recoverPSS(umbral, numero_shares); //Recuperacion llave
    std::cout << "OK" << std::endl;

    std::cout << "Recover IDA..." << std::flush;
    archivo.recoverIDA(umbral, numero_shares); //Recuperacion archivo
    std::cout << "OK" << std::endl;

    std::cout << "Descifrando archivo..." << std::flush;
    archivo.descifrar(llave, iv); //Descifrado
    std::cout << "OK" << std::endl;

    //Borrar los que si se lograron recuperar
    std::cout << "Borrando archivos auxiliares..." << std::flush;
    for (auto &fragmento : fragmentos) {
        fragmento.borra();
    }
    std::cout << "OK" << std::endl;

    std::cout << "El archivo se recupero correctamente" << std::endl;

    //Transfiere el archivo desde la maquina actual al servidor web    
    std::string comando_distribucion = "scp " + nombre_archivo + " " + servidor_remoto + ":/" + ubicacion_remota;
    std::cout << "Comando transferencia:" << comando_distribucion << std::endl;
    system(comando_distribucion.c_str());

    return 0;
}

