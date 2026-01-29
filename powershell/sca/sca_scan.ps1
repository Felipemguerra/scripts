Set-ExecutionPolicy AllSigned -Scope Process -Force
$ProgressPreference = "silentlyContinue"; iex ((New-Object System.Net.WebClient).DownloadString('https://sca-downloads.veracode.com/ci.ps1'))
mvn dependency:tree > tree.txt
$Env:SRCCLR_DEPENDENCY_TREE_FILE='tree.txt'
srcclr scan --stdin=maven --allow-dirty