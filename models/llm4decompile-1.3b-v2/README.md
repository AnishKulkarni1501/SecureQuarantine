---
license: mit
tags:
- decompile
- binary
widget:
 - text: "# This is the assembly code:\nfloat func0(float param_1)\n\n{\n  return param_1 - (float)(int)param_1;\n}# What is the source code?\n"
---


### 1. Introduction of LLM4Decompile

LLM4Decompile aims to decompile x86 assembly instructions into C. The newly released V2 series are trained with a larger dataset (2B tokens) and a maximum token length of 4,096, with remarkable performance (up to 100% improvement) compared to the previous model.

- **Github Repository:** [LLM4Decompile](https://github.com/albertan017/LLM4Decompile)


### 2. Evaluation Results

|         Metrics         | Re-executability Rate |         |         |         |         | Edit Similarity |         |         |         |         |
|:-----------------------:|:---------------------:|:-------:|:-------:|:-------:|:-------:|:---------------:|:-------:|:-------:|:-------:|:-------:|
|    Optimization Level   |           O0          |    O1   |    O2   |    O3   |   AVG   |        O0       |    O1   |    O2   |    O3   |   AVG   |
|  LLM4Decompile-End-6.7B |        0.6805         | 0.3951  | 0.3671  | 0.3720  | 0.4537  |     0.1557      | 0.1292  | 0.1293  | 0.1269  | 0.1353  |
|          Ghidra         |        0.3476         | 0.1646  | 0.1524  | 0.1402  | 0.2012  |     0.0699      | 0.0613  | 0.0619  | 0.0547  | 0.0620  |
|         +GPT-4o         |        0.4695         | 0.3415  | 0.2866  | 0.3110  | 0.3522  |     0.0660      | 0.0563  | 0.0567  | 0.0499  | 0.0572  |
| +LLM4Decompile-Ref-1.3B |        0.6890         | 0.3720  | 0.4085  | 0.3720  | 0.4604  |     0.1517      | 0.1325  | 0.1292  | 0.1267  | 0.1350  |
| +LLM4Decompile-Ref-6.7B |        0.7439         | 0.4695  | 0.4756  | 0.4207  | 0.5274  |     0.1559      | 0.1353  | 0.1342  | 0.1273  | 0.1382  |
|  +LLM4Decompile-Ref-33B |        0.7073         | 0.4756  | 0.4390  | 0.4146  | 0.5091  |     0.1540      | 0.1379  | 0.1363  | 0.1307  | 0.1397  |

### 3. How to Use
Here is an example of how to use our model (Only for V2. For previous models, please check the corresponding model page at HF).

1. Install Ghidra
Download [Ghidra](https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.3_build/ghidra_11.0.3_PUBLIC_20240410.zip) to the current folder. You can also check the [page](https://github.com/NationalSecurityAgency/ghidra/releases) for other versions. Unzip the package to the current folder.
In bash, you can use the following:
```bash
cd LLM4Decompile/ghidra
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.3_build/ghidra_11.0.3_PUBLIC_20240410.zip
unzip ghidra_11.0.3_PUBLIC_20240410.zip
```
2. Install Java-SDK-17
Ghidra 11 is dependent on Java-SDK-17, a simple way to install the SDK on Ubuntu:
```bash
apt-get update
apt-get upgrade
apt install openjdk-17-jdk openjdk-17-jre
```
Please check [Ghidra install guide](https://htmlpreview.github.io/?https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_11.1.1_build/GhidraDocs/InstallationGuide.html) for other platforms. 

3. Use Ghidra Headless to decompile binary (demo.py)

Note: **Replace** func0 with the function name you want to decompile.

**Preprocessing:** Compile the C code into binary, and disassemble the binary into assembly instructions.
```python
import os
import subprocess
from tqdm import tqdm,trange

OPT = ["O0", "O1", "O2", "O3"]
timeout_duration = 10

ghidra_path = "./ghidra_11.0.3_PUBLIC/support/analyzeHeadless"#path to the headless analyzer, change the path accordingly
postscript = "./decompile.py"#path to the decompiler helper function, change the path accordingly
project_path = "."#path to temp folder for analysis, change the path accordingly
project_name = "tmp_ghidra_proj"
func_path = "../samples/sample.c"#path to c code for compiling and decompiling, change the path accordingly
fileName = "sample"

with tempfile.TemporaryDirectory() as temp_dir:
    pid = os.getpid()
    asm_all = {}
    for opt in [OPT[0]]:
        executable_path = os.path.join(temp_dir, f"{pid}_{opt}.o")
        cmd = f'gcc -{opt} -o {executable_path} {func_path} -lm'
        subprocess.run(
        cmd.split(' '),
        check=True,
        stdout=subprocess.DEVNULL,  # Suppress stdout
        stderr=subprocess.DEVNULL,  # Suppress stderr
        timeout=timeout_duration,
        )

        output_path = os.path.join(temp_dir, f"{pid}_{opt}.c")
        command = [
            ghidra_path,
            temp_dir,
            project_name,
            "-import", executable_path,
            "-postScript", postscript, output_path,
            "-deleteProject",  # WARNING: This will delete the project after analysis
        ]
        result = subprocess.run(command, text=True, capture_output=True, check=True)
        with open(output_path,'r') as f:
            c_decompile = f.read()
        c_func = []
        flag = 0
        for line in c_decompile.split('\n'):
            if "Function: func0" in line:#**Replace** func0 with the function name you want to decompile.
                flag = 1
                c_func.append(line)
                continue
            if flag:
                if '// Function:' in line:
                    if len(c_func) > 1:
                        break
                c_func.append(line)
        if flag == 0:
            raise ValueError('bad case no function found')
        for idx_tmp in range(1,len(c_func)):##########remove the comments
            if 'func0' in c_func[idx_tmp]:
                break
        c_func = c_func[idx_tmp:]
        input_asm = '\n'.join(c_func).strip()

        before = f"# This is the assembly code:\n"#prompt
        after = "\n# What is the source code?\n"#prompt
        input_asm_prompt = before+input_asm.strip()+after
        with open(fileName +'_' + opt +'.pseudo','w',encoding='utf-8') as f:
            f.write(input_asm_prompt)
```

Ghidra pseudo-code may look like this:
```c
undefined4 func0(float param_1,long param_2,int param_3)
{
  int local_28;
  int local_24;
  
  local_24 = 0;
  do {
    local_28 = local_24;
    if (param_3 <= local_24) {
      return 0;
    }
    while (local_28 = local_28 + 1, local_28 < param_3) {
      if ((double)((ulong)(double)(*(float *)(param_2 + (long)local_24 * 4) -
                                  *(float *)(param_2 + (long)local_28 * 4)) &
                  SUB168(_DAT_00402010,0)) < (double)param_1) {
        return 1;
      }
    }
    local_24 = local_24 + 1;
  } while( true );
}
```
4. Refine pseudo-code using LLM4Decompile (demo.py)

**Decompilation:** Use LLM4Decompile-Ref to refine the Ghidra pseudo-code into C:
```python
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch

model_path = 'LLM4Binary/llm4decompile-6.7b-v2' # V2 Model
tokenizer = AutoTokenizer.from_pretrained(model_path)
model = AutoModelForCausalLM.from_pretrained(model_path, torch_dtype=torch.bfloat16).cuda()

with open(fileName +'_' + OPT[0] +'.pseudo','r') as f:#optimization level O0
    asm_func = f.read()
inputs = tokenizer(asm_func, return_tensors="pt").to(model.device)
with torch.no_grad():
    outputs = model.generate(**inputs, max_new_tokens=2048)### max length to 4096, max new tokens should be below the range
c_func_decompile = tokenizer.decode(outputs[0][len(inputs[0]):-1])

with open(fileName +'_' + OPT[0] +'.pseudo','r') as f:#original file
    func = f.read()

print(f'pseudo function:\n{func}')# Note we only decompile one function, where the original file may contain multiple functions
print(f'refined function:\n{c_func_decompile}')

```

### 4. License
This code repository is licensed under the MIT License.

### 5. Contact

If you have any questions, please raise an issue.
