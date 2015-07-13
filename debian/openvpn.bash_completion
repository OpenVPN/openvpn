# bash completion for openvpn init.d script
# Written by Alberto Gonzalez Iniesta <agi@inittab.org>

_openvpn()
{

  local cur 

  COMPREPLY=()
  cur=${COMP_WORDS[COMP_CWORD]}

  if [ $COMP_CWORD -eq 1 ] ; then
    COMPREPLY=( $( compgen -W '$( /etc/init.d/openvpn 2>&1 \
              | cut -d"{" -f2 | tr -d "}" | tr "|" " " )' -- $cur ) )
  else
    COMPREPLY=( $( compgen -W '$( command ls /etc/openvpn/*.conf 2>/dev/null \
              | sed -e 's%/etc/openvpn/%%' -e 's/\.conf//' )' -- $cur ) )
  fi

}


complete -F _openvpn /etc/init.d/openvpn
