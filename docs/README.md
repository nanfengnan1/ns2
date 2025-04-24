install tutorials

1. install deps

  ```bash
  sudo apt-get install -y --no-install-recommends build-essential \
      tcl8.5 tcl8.5-dev tk8.5 tk8.5-dev \
      libxmu-dev libxmu-headers g++-4.8 \
      libssl-dev
  ````

2. download and compile source code

  2.1 download source code

  ```bash
  git clone git@github.com:nanfengnan1/ns2.git
  ```

  or

  ```bash
  wget http://sourceforge.net/projects/nsnam/files/allinone/ns-allinone-2.35/ns-allinone-2.35.tar.gz
  tar zxvf ns-allinone-2.35.tar.gz -C /home/alexan/program/ns2
  ```
  
  2.2 compile source code

  you could build your source code in /home/alexan/program/ns2/ns-allinone-2.35/
  ```bash
  cd /home/alexan/program/ns2/ns-allinone-2.35/
  export CC=gcc-4.8 CXX=g++-4.8 && ./install
  ```

3. modify user envirment variable

  append this config to ~./bashrc

  ```bash
  export CC=gcc-4.8 CXX=g++-4.8

  NS2_HOME="/home/alexan/program/ns2/ns-allinone-2.35"
  export PATH="$PATH:$NS2_HOME/bin:$NS2_HOME/tcl8.5.10/unix:$NS2_HOME/tk8.5.10/unix"
  export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$NS2_HOME/otcl-1.14:$NS2_HOME/lib"
  export TCL_LIBRARY="$TCL_LIBRARY:$NS2_HOME/tcl8.5.10/library
  ``` 

4. compile nam

  ```bash
  cd /home/alexan/program/ns2/ns-allinone-2.35/nam-1.15
  ./configure && make -j`nproc` && sudo make install
  ```

5. test ns2

  ```bash
  cd /home/alexan/program/ns2/ns-allinone-2.35/ns-2.35/tcl/ex
  ns simple.tcl
  ```
