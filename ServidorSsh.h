#ifndef SERVIDORSSH_H
#define SERVIDORSSH_H
#include <string>
#include <vector>

class ServidorSsh {
public:
    ServidorSsh(std::string);
    bool copiaHome(std::vector<std::string>, std::string, std::string);
    bool recuperaHome(std::vector<std::string>, std::string, std::string);
    ServidorSsh(const ServidorSsh& orig);
    virtual ~ServidorSsh();
private:
    std::string usuario_host;
};

#endif /* SERVIDORSSH_H */

