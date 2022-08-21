-- https://github.com/vmmcall/overwatch-iat-fixer

function string:split(delimeter)
    local result = {}
    for each in self:gmatch("[^%"..delimeter.."]+") do
        table.insert(result, each)
    end
    return result
end

function disasm(addr)
    local size = getInstructionSize(addr)
    local disassStr = disassemble(addr)
    local extraField, opcode, bytes, address = splitDisassembledString(disassStr)
    return opcode, size
end

function isR64(data)
    local r64 = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"}
    for i, v in ipairs(r64) do
        if v == data then
            return true
        end
    end
    return false
end

function follow(addr)
    local address = addr
    local r64 = {}
    while true do
        local opcode, size = disasm(address)
        local mnemonic = opcode:split(" ")
        local route = mnemonic[2]:split(",")
        address = address + size
        if mnemonic[1] == "mov" then
            if isR64(route[1]) and isR64(route[2]) then
                r64[route[1]] = r64[route[2]]
            elseif isR64(route[1]) and not isR64(route[2]) then
                r64[route[1]] = tonumber(route[2], 16)
            end
        elseif mnemonic[1] == "xor" then
            if isR64(route[1]) and isR64(route[2]) then
                r64[route[1]] = bXor(r64[route[1]], r64[route[2]])
            elseif isR64(route[1]) and not isR64(route[2]) then
                r64[route[1]] = bXor(r64[route[1]], tonumber(route[2], 16))
            end
        elseif mnemonic[1] == "add" then
            if isR64(route[1]) and isR64(route[2]) then
                r64[route[1]] = r64[route[1]] + r64[route[2]]
            elseif isR64(route[1]) and not isR64(route[2]) then
                r64[route[1]] = r64[route[1]] + tonumber(route[2], 16)
            end
        elseif mnemonic[1] == "sub" then
            if isR64(route[1]) and isR64(route[2]) then
                r64[route[1]] = r64[route[1]] - r64[route[2]]
            elseif isR64(route[1]) and not isR64(route[2]) then
                r64[route[1]] = r64[route[1]] - tonumber(route[2], 16)
            end
        elseif mnemonic[1] == "or" then
            if isR64(route[1]) and isR64(route[2]) then
                r64[route[1]] = bOr(r64[route[1]], r64[route[2]])
            elseif isR64(route[1]) and not isR64(route[2]) then
                r64[route[1]] = bOr(r64[route[1]], tonumber(route[2], 16))
            end
        elseif mnemonic[1] == "imul" then
            if isR64(route[1]) and isR64(route[2]) then
                r64[route[1]] = r64[route[1]] * r64[route[2]]
            elseif isR64(route[1]) and not isR64(route[2]) then
                r64[route[1]] = r64[route[1]] * tonumber(route[2], 16)
            end
        elseif mnemonic[1] == "jmp" then
            if isR64(mnemonic[2]) then
                return r64[mnemonic[2]]
            else
                address = tonumber(mnemonic[2], 16)
            end
        end
    end
end

function fix()
    local base = getAddress("Overwatch.exe")
    local NtHeaders = base + readInteger(base + 0x3C)
    local sectionCount = readSmallInteger(NtHeaders + 6)
    for i = 0, sectionCount - 1 do
        local section = NtHeaders + 0x108 + 0x28 * i
        local name = readString(section, 8, false)
        if name == ".rdata" then
            local va = readInteger(section + 0x0C)
            local iat = base + va
            local addr = readPointer(iat)
            repeat
                if addr ~= 0 then
                    local dest = follow(addr)
                    local scriptStr = [[%x:
                            jmp %x
                        ]]
                    if inModule(dest) then 
                        autoAssemble(string.format(scriptStr, addr, dest))
                    end
                    print(string.format("%x - %s", addr, getNameFromAddress(dest)))
                end
                iat = iat + 8
                addr = readPointer(iat)
            until inModule(addr)
            break
        end
    end
end

fix()
