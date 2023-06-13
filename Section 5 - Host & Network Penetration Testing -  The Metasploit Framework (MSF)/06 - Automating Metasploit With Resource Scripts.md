--- 

- Metasploit resource scripts are a great feature of MSF that allow you to automate repetitive tasks and commands.

- They operate similarly to batch scripts, whereby, you can specify a set of

- Msfconsole commands that you want to execute sequentially.

- You can the load the script with Msfconsole and automate the execution of the commands you specified in the resource script.

- We can use resource scripts to automate various tasks like setting up multi handlers as well as loading and executing payloads.

- The default resource scripts path is: `/usr/share/metasploit-framework/scripts/resource`

``` bash
msfconsole -r file.rc 
# -r, --resource FILE Execute the specified resource file (- for stdin)
`