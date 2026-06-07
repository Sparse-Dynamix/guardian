# Dot-source from Windows-native scripts: Strawberry Perl + LLVM for Frida bindgen/OpenSSL.
$llvm = "C:\Program Files\LLVM\bin"
$perl = "C:\Strawberry\perl\bin"
if (Test-Path $perl) { $env:Path = "$perl;$env:Path" }
if (Test-Path $llvm) {
    $env:Path = "$llvm;$env:Path"
    $env:LIBCLANG_PATH = $llvm
}
