#!/bin/zsh
export MODULE_LIST=`tree . -f`
export STANDARD_MODULE_STRUCT=`cat ./metasploit-modules-folder-structure.md`

cat <<EOF > README.md
# Self Metasploit

Esonhugh self maintained Metasploit modules folder

## Usage

\`\`\`bash
git clone https://github.com/Esonhugh/Self-Metasploit.git
echo "loadpath \${PWD}/Self-Metasploit" >> \$HOME/.msf4/msfconsole.rc
\`\`\`

> put into command loadpath \$PWD/Self-Metasploit into \$HOME/.msf4/msfconsole.rc file
> 
> That will make metasploit auto loading modules from Self-Metasploit folder when msfconsole start without -r options
>

## Modules List

\`\`\`
${MODULE_LIST}
\`\`\`

## Standard Modules folder list in Metasploit

\`\`\`
${STANDARD_MODULE_STRUCT}
\`\`\`

EOF