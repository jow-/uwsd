#!/bin/sh

printf "Content-Type: text/html; charset=utf-8\r\n\r\n"

cat <<EOT
<html>
  <head>
    <title>System Time</title>
    <meta http-equiv="refresh" content="1; /cgi-bin/time.cgi">
   </head>
   <body>
     <h1>System time</h1>
     <p>
       The current system time is <strong>$(date)</strong>.
     </p>
   </body>
</html>
EOT
