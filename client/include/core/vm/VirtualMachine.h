#pragma once

#include <QString>
#include <vector>

namespace core {

struct VMInstruction
{
    quint8 opcode = 0;
    std::vector<quint8> operands;
};

class VirtualMachine
{
public:
    VirtualMachine();

    void reset();
    void loadProgram(const std::vector<VMInstruction> &program);
    bool execute();

private:
    std::vector<VMInstruction> program_;
};

} // namespace core
