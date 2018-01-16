#!/usr/bin/env bash

AUTOSSH_ROOT=$HOME/.autossh

if [ -z $1 ]; then
    echo "Please enter shell profile path"
    echo "Just like ~/.zshrc ~/.bashrc"
    exit 1
fi

if [ ! -d $AUTOSSH_ROOT ]; then
    mkdir -p $AUTOSSH_ROOT/bin
fi

echo "export AUTOSSH_ROOT=$AUTOSSH_ROOT" >> $1
echo "export PATH=\$AUTOSSH_ROOT/bin:\$PATH" >> $1
export AUTOSSH_ROOT=$AUTOSSH_ROOT
export PATH=$AUTOSSH_ROOT/bin:$PATH

cp -f autossh $AUTOSSH_ROOT/bin
cp -f autossh.py $AUTOSSH_ROOT/bin
chmod +x $AUTOSSH_ROOT/bin/autossh

#####################################
cat > remove.sh <<EOF
#!/usr/bin/env bash

sed -ie '/export =.*/d' $1
sed -ie '/export PATH=\$\/bin:\$PATH/d' $1

rm -rf $
rm -f remove.sh
EOF
chmod +x remove.sh