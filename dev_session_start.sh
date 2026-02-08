#!/usr/bin/env bash

unset SESSION_MANAGER
unset DBUS_SESSION_BUS_ADDRESS

while ( true ); do
  /usr/bin/xfce4-session --display :0
done;
