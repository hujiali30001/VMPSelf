#pragma execution_character_set("utf-8")

#include "core/vm/VirtualMachine.h"

#include "core/util/Logger.h"

namespace core {

VirtualMachine::VirtualMachine() = default;

void VirtualMachine::reset()
{
    program_.clear();
    Logger::instance().log("VirtualMachine: 状态已重置");
}

void VirtualMachine::loadProgram(const std::vector<VMInstruction> &program)
{
    program_ = program;
    Logger::instance().log(QString("VirtualMachine: 加载指令数 %1").arg(program_.size()));
}

bool VirtualMachine::execute()
{
    Logger::instance().log("VirtualMachine: 执行开始 (占位实现)");
    // TODO: 实现指令解释器 / JIT
    return true;
}

} // namespace core
