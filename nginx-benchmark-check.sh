#!/bin/bash

# ****************************************************************
# * File                      : nginx-benchmark-check.sh         *
# * Project                   : NGINX Benchmark                  *
# * Author                    : Viduranga Randila                *
# * Compiler                  : Bash                             *
# * Date                      : 2020-12-06                       *
# ****************************************************************

#RED='\033[0;31m'
RED='\033[91m'
D_RED='\033[0;31m'
BLUE='\033[0;34m'
D_GRAY='\033[1;30m'
GREEN='\033[0;32m'
WBLUE='\033[44m'
#YELLOW='\033[1;33m'
ORANGE='\033[0;33m'
LGREEN='\033[1;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'
UNN='\033[5m'
BICyan='\033[1;96m'
IBlue='\033[0;94m'  
IYellow='\033[0;93m' 
IGreen='\033[0;92m'
_score=0
_title=0

_secore_module=0
_secore_security=0
_secore_ownership=0
_secore_network=0
_secore_info=0
_secore_logging=0
_secore_ssl=0
_secore_limit=0
_secore_browser=0

function _print_banner {
        clear
        echo " "
        echo " "
        tput rev
        echo -e "${YELLOW}##################################################"
        echo -e "${YELLOW}#                                                #"
        echo -e "${YELLOW}#             NGINX BENCHMARK TEST               #"
        echo -e "${YELLOW}#                                                #"
        echo -e "${YELLOW}##################################################${NC}"
        tput sgr0
        echo " "
        echo " "

}

function _check_dev_module
{
	_title=`expr $_title + 1`

	echo -e "${IGreen}$_title.Minimize NGINX Modules${NC}"
	echo ""
	_status=`nginx -V 2>&1 | grep http_dav_module| wc -l`
	if [ $_status -gt 0 ];
	then
		echo -e "${ORANGE}${BOLD}DEV Module Disable  : ${RED}${UNN}FAIL${NC}"
		echo ""
		echo -e "${ORANGE}${BOLD}Description${NC}"
		echo -e "${BLUE}Mostmodern architectures have replaced this functionality with cloud-based object storage, in
which case the module should not be installed${NC}"
		echo ""
		echo -e "${ORANGE}${BOLD}Remediation${NC}"
		echo -e "${BLUE}To remove the http_dav_module, recompile nginx from source without the --with-http_dav_module flag.${NC}"
		echo ""
	else
		echo -e "${ORANGE}${BOLD}DEV Module Disable  : ${GREEN}PASS${NC}"
		echo ""
		_secore_module=`expr $_secore_module + 1`
	fi
}

function _check_gzip_module
{
        _status=`nginx -V 2>&1 | grep http_dav_module| wc -l`
        if [ $_status -gt 0 ];
        then
                echo -e "${ORANGE}${BOLD}GZIP Module Disable : ${RED}${UNN}FAIL${NC}"
		echo ""
		echo -e "${ORANGE}${BOLD}Description${NC}"
                echo -e "${BLUE}gzip is used for compression. Compression functionality should be disabled to prevent 
certain types of attacks from being performed successfully.${NC}"
                echo ""
		echo -e "${ORANGE}${BOLD}Remediation${NC}"
		echo -e "${BLUE}Recompile without the --with-http_gzip_static_module configuration directive.${NC}"
		echo ""
        else
                echo -e "${ORANGE}${BOLD}GZIP Module Disable : ${GREEN}PASS${NC}"
		echo ""
		_secore_module=`expr $_secore_module + 1`
        fi
}

function _check_auto_index
{
	_status1=`egrep -i '^\s*autoindex\s+' /etc/nginx/nginx.conf | wc -l`
	_status2=`egrep -ir '^\s*autoindex\s+' /etc/nginx/conf.d/* | wc -l`

	if [ $_status1 -gt 0 ] || [ $_status2 -gt 0 ];
	then
		echo -e "${ORANGE}${BOLD}Autoindex Disable : ${RED}${UNN}FAIL${NC}"
		echo ""
		echo -e "${ORANGE}${BOLD}Description${NC}"
		echo -e "${BLUE}The autoindex module processes requests ending with the slash character. This feature
enables directory listing, which could be useful in attacker reconnaissance, so it should be disabled.${NC}"
		echo ""
		echo -e "${ORANGE}${BOLD}Remediation${NC}"
		echo -e "${BLUE}Set the value for all autoindex directives to off, or remove those directives${NC}"
		echo ""
	else
		echo -e "${ORANGE}${BOLD}Autoindex Disable : ${GREEN}PASS${NC}"
		_secore_module=`expr $_secore_module + 1`
		echo ""
	fi
}

function _check_nginx_user
{
	_title=`expr $_title + 1`

        echo -e "${IGreen}$_title.Nginx Account Security${NC}"
        echo ""

	_status=`grep "user[^;]*;" /etc/nginx/nginx.conf | wc -l`
	
	if [ $_status -gt 0 ];
	then
		echo -e "${ORANGE}${BOLD}Nginx is being run as a dedicated user : ${GREEN}PASS${NC}"
		_secore_security=`expr $_secore_security + 1`
	else
		echo -e "${ORANGE}${BOLD}Nginx is being run as a dedicated user : ${RED}${UNN}FAIL${NC}"
	fi

#------------------------------------Nginx user is not privileged-----------------------------------------

	_status=`sudo -l -U nginx`
	
	if [[ $_status == *"not allowed"* ]];
	then
		echo -e "${ORANGE}${BOLD}Nginx user is not privileged : ${GREEN}PASS${NC}"
		_secore_security=`expr $_secore_security + 1`
	else
		echo -e "${ORANGE}${BOLD}Nginx user is not privileged : ${RED}${UNN}FAIL${NC}"
	fi

#-------------------------------ginx user is not part of any unexpected groups--------------------------

	_status=`groups nginx| cut -d' ' -f4`

	if [[ $_status == "" ]];
	then
		echo -e "${ORANGE}${BOLD}Nginx user is not part of any unexpected groups : ${GREEN}PASS${NC}"
		_secore_security=`expr $_secore_security + 1`
	else
		echo -e "${ORANGE}${BOLD}Nginx user is not part of any unexpected groups : ${RED}${UNN}FAIL${NC}"
	fi

#----------------------------------------Nginx user login shell-------------------------------------------

	_status=`grep nginx /etc/passwd| cut -d':' -f7`
	
	if [[ $_status == "/sbin/nologin" ]];
	then
		echo -e "${ORANGE}${BOLD}Nginx user login shell /sbin/nologin : ${GREEN}PASS${NC}"
		_secore_security=`expr $_secore_security + 1`
	else
		echo -e "${ORANGE}${BOLD}Nginx user login shell /sbin/nologin : ${RED}${UNN}FAIL${NC}"
		echo ""
		echo -e "${ORANGE}${BOLD}Remediation${NC}"
		echo -e "${BLUE}Add a system account for the nginx user with a home directory of /var/cache/nginx and a shell of
/sbin/nologin so it does not have the ability to log in, then add the nginx user to be used by nginx${NC}"
		echo ""
		echo -e "${IBlue}Command: chsh -s /sbin/nologin nginx${NC}"
                echo ""
	fi

#-----------------------------------------Nginx service account is locked--------------------------------------

	_status=`passwd -S nginx`
	
	if [[ $_status == *"Password locked"* ]] || [[ $_status == *"-1 -1 -1 -1"* ]];
	then
		echo -e "${ORANGE}${BOLD}Nginx service account is locked : ${GREEN}PASS${NC}"
		_secore_security=`expr $_secore_security + 1`
	else
		echo -e "${ORANGE}${BOLD}Nginx service account is locked : ${RED}${UNN}FAIL${NC}"
		echo ""
		echo -e "${ORANGE}${BOLD}Remediation${NC}"
		echo -e "${BLUE}Use the passwd command to lock the nginx service account${NC}"
		echo ""
		echo -e "${IBlue}Command: passwd -l nginx${NC}"
		echo ""
	fi
}

#-------------------------------------------------------------------------------------------------------------

function _check_file_ownerwhip
{
	_title=`expr $_title + 1`

	echo ""
        echo -e "${IGreen}$_title.Permissions and Ownership${NC}"
        echo ""	
	
	_status1=`find /etc/nginx/ -not -user root | wc -l`
	_status2=`find /etc/nginx/ -not -group root | wc -l`

	if [ $_status1 -gt 0 ] || [ $_status2 -gt 0 ];
	then
		echo -e "${ORANGE}${BOLD}NGINX config file /etc/nginx/ ownerwhip check : ${RED}${UNN}FAIL${NC}"
		echo ""
		echo -e "${BLUE}Below files/directories belongs to different user or group${IBlue}"
		echo ""
		find /etc/nginx/ -not -user root | xargs ls -ld
		find /etc/nginx/ -not -group root | xargs ls -ld
		echo -e "${NC}"
		echo -e "${ORANGE}${BOLD}Remediation${NC}"
		echo -e "${BLUE}Setting ownership to only those users in the root group and the root user will reduce the
likelihood of unauthorized modifications to the nginx configuration files${NC}"
		echo ""
		echo -e "${IBlue}Command: chown -R root:root /etc/nginx${NC}"
		echo ""
	else
		echo -e "${ORANGE}${BOLD}NGINX config file /etc/nginx/ ownerwhip check : ${GREEN}PASS${NC}"
		_secore_ownership=`expr $_secore_ownership + 1`
		#echo ""
	fi
}

function _check_file_permission
{
	_status1=`find /etc/nginx/ -type d -not -perm 750 | wc -l`
	_status2=`find /etc/nginx/ -type f -not -perm 640 | grep -vE "*.key" | wc -l`

        if [ $_status1 -gt 0 ] || [ $_status2 -gt 0 ];
        then
                echo -e "${ORANGE}${BOLD}NGINX config file /etc/nginx/ permission check : ${RED}${UNN}FAIL${NC}"
                echo ""
                echo -e "${BLUE}Below files/directories don't have recommended permissions${IBlue}"
		echo ""
                find /etc/nginx/ -type d -not -perm 750 | xargs ls -ld
		find /etc/nginx/ -type f -not -perm 640| grep -vE "*.key" | xargs ls -ld
                echo -e "${NC}"
                echo -e "${ORANGE}${BOLD}Remediation${NC}"
                echo -e "${BLUE}This ensures that only users who need access to configuration files are able to view them,
thus preventing unauthorized access. Other users will need to use sudo in order to accessthese files${NC}"
		echo ""
                echo -e "${IBlue}Command: find /etc/nginx -type d | xargs chmod 750; find /etc/nginx -type f | xargs chmod 640${NC}"
                echo ""
        else
                echo -e "${ORANGE}${BOLD}NGINX config file /etc/nginx/ permission check : ${GREEN}PASS${NC}"
		_secore_ownership=`expr $_secore_ownership + 1`
                #echo ""
        fi
}

function _check_nginx_pid_file
{

#-----------------------------------------------nginx.pid ownerwhip check------------------------------------------------

        _status1=`find /var/run/nginx.pid -not -user root | wc -l`
        _status2=`find /var/run/nginx.pid -not -group root | wc -l`

        if [ $_status1 -gt 0 ] || [ $_status2 -gt 0 ];
        then
                echo -e "${ORANGE}${BOLD}NGINX PID file /var/run/nginx.pid ownerwhip check : ${RED}${UNN}FAIL${NC}"
                echo ""
                echo -e "${BLUE}Below files/directories belongs to different user or group${IBlue}"
                echo ""
                find /var/run/nginx.pid -not -user root | xargs ls -ld
                find /var/run/nginx.pid -not -group root | xargs ls -ld
                echo -e "${NC}"
                echo -e "${ORANGE}${BOLD}Remediation${NC}"
                echo -e "${BLUE}The PID file should be owned by root and the group root. This will prevent unauthorized modification of the PID file,
which could cause a denial of service${NC}"
		echo ""
                echo -e "${IBlue}Command: chown root:root /var/run/nginx.pid${NC}"
                echo ""
        else
                echo -e "${ORANGE}${BOLD}NGINX PID file /var/run/nginx.pid ownerwhip check : ${GREEN}PASS${NC}"
		_secore_ownership=`expr $_secore_ownership + 1`
        fi

#----------------------------------------------/var/run/nginx.pid permission check---------------------------------------------

        _status=`find /var/run/nginx.pid -not -perm 644 | wc -l`

        if [ $_status -gt 0 ];
        then
                echo -e "${ORANGE}${BOLD}NGINX PID file /var/run/nginx.pid permission check : ${RED}${UNN}FAIL${NC}"
                echo ""
                echo -e "${BLUE}NGINX PIN file don't have recommended permissions${IBlue}"
                echo ""
		find /var/run/nginx.pid -not -perm 644 | xargs ls -ld
                echo -e "${NC}"
                echo -e "${ORANGE}${BOLD}Remediation${NC}"
                echo -e "${BLUE}File should be readable to everyone,but only writable by root (permissions 644). This will prevent
unauthorized modification of the PID file${NC}"
		echo ""
                echo -e "${IBlue}Command: chmod 644 /var/run/nginx.pid${NC}"
                echo ""
        else
                echo -e "${ORANGE}${BOLD}NGINX PID file /var/run/nginx.pid permission check : ${GREEN}PASS${NC}"
		_secore_ownership=`expr $_secore_ownership + 1`
        fi

#--------------------------------------------nginx files ownerwhip check-----------------------------------------------------

        _status1=`find /var/log/nginx -not -user nginx | wc -l`
        _status2=`find /var/log/nginx -not -group root | wc -l`

        if [ $_status1 -gt 0 ] || [ $_status2 -gt 0 ];
        then
                echo -e "${ORANGE}${BOLD}NGINX /var/log/nginx files ownerwhip check : ${RED}${UNN}FAIL${NC}"
                echo ""
                echo -e "${BLUE}Below files/directories belongs to different user or group${IBlue}"
                echo ""
                find /var/log/nginx -not -user nginx | xargs ls -ld
                find /var/log/nginx -not -group root | xargs ls -ld
                echo -e "${NC}"
                echo -e "${ORANGE}${BOLD}Remediation${NC}"
                echo -e "${BLUE}Files should owned by nginx and has a group ownership of the root group${NC}"
		echo ""
                echo -e "${IBlue}Command: chown -R nginx:root /var/log/nginx${NC}"
                echo ""
        else
                echo -e "${ORANGE}${BOLD}NGINX /var/log/nginx files ownerwhip check : ${GREEN}PASS${NC}"
		_secore_ownership=`expr $_secore_ownership + 1`
        fi

#-----------------------------------------------/var/log/nginx permission check----------------------------------------------

        _status1=`find /var/log/nginx -type d -not -perm 750 | wc -l`
        _status2=`find /var/log/nginx -type f -not -perm 640 | wc -l`

        if [ $_status1 -gt 0 ] || [ $_status2 -gt 0 ];
        then
                echo -e "${ORANGE}${BOLD}NGINX /var/log/nginx permission check : ${RED}${UNN}FAIL${NC}"
                echo ""
                echo -e "${BLUE}Below files don't have recommended permissions${IBlue}"
                echo ""
                find /var/log/nginx -type d -not -perm 750 | xargs ls -ld
		find /var/log/nginx -type f -not -perm 640 | xargs ls -ld
                echo -e "${NC}"
                echo -e "${ORANGE}${BOLD}Remediation${NC}"
                echo -e "${BLUE}Should not have read-write-search access permission for other users${NC}"
		echo ""
                echo -e "${IBlue}Command: chmod 750 /var/log/nginx; chmod -r 640 /var/log/nginx/* ${NC}"
                echo ""
        else
                echo -e "${ORANGE}${BOLD}NGINX /var/log/nginx permission check : ${GREEN}PASS${NC}"
		_secore_ownership=`expr $_secore_ownership + 1`
        fi
}

#-----------------------------------------------------------------------------------------------------------------------------

function _check_nginx_network
{
	_title=`expr $_title + 1`

        echo ""
        echo -e "${IGreen}$_title.Network Configuration${NC}"
        echo ""	

#-----------------------------------------------NGINX Listen on default Port---------------------------------------------------
	
	_status=`netstat -anp| grep nginx| grep LISTEN| cut -d':' -f2| cut -d' ' -f1| grep -vw 80 | grep -ve 443 | wc -l`

	if [ $_status -gt 0 ];
	then
		echo -e "${ORANGE}${BOLD}NGINX Listen on default Port : ${RED}${UNN}FAIL${NC}"
		echo ""
		echo -e "${BLUE}NGINX listen non standerd port${IBlue}"
		echo ""
		netstat -anp| grep nginx| grep LISTEN| grep -vw 80 | grep -ve 443
		echo -e "${NC}"
		echo -e "${ORANGE}${BOLD}Remediation${NC}"
		echo -e "${BLUE}If any ports are listening that are not authorized, comment out or delete the associated
configuration for that listener.${NC}"
		echo ""
	else
		echo -e "${ORANGE}${BOLD}NGINX Listen on default Port : ${GREEN}PASS${NC}"
		#_score=`expr $_score + 1`
	fi

#-----------------------------------------------Unknown host names are rejected--------------------------------------------------

	_status=`curl -s -I http://127.0.0.1 -H "Host: invalid.doman.local" | grep HTTP| grep -w 200 | wc -l`

	if [ $_status -gt 0 ];
	then
		echo -e "${ORANGE}${BOLD}Unknown host names are rejected : ${RED}${UNN}FAIL${NC}"
		echo ""
		echo -e "${BLUE}NGINX responced to unknown hostname request."
		echo -e "curl -s -I http://127.0.0.1 -H \"Host: invalid.doman.local\"${IBlue}"
		echo ""
		curl -s -I http://127.0.0.1 -H "Host: invalid.doman.local"
		#echo -e "${NC}"
		echo -e "${ORANGE}${BOLD}Remediation${NC}"
		echo -e "${BLUE}Ensure your first server block mirrors the below in your nginx configuration, either at
/etc/nginx/nginx.conf or any included file within your nginx config"
		echo ""
		echo -e "${IBlue}server {
    listen 80 default_server;
    server_name _;
    return 404;
}${NC}"
		echo ""

	else
		echo -e "${ORANGE}${BOLD}Unknown host names are rejected : ${GREEN}PASS${NC}"
		_secore_network=`expr $_secore_network + 1`
	fi

#--------------------------------------------NGINX keepalive_timeout variable set-----------------------------------------------

	_status=`grep -i keepalive_timeout /etc/nginx/nginx.conf | wc -l`

	if [ $_status -gt 0 ];
	then
		#echo -e "${ORANGE}${BOLD}NGINX keepalive_timeout variable set : ${GREEN}PASS${NC}"
		_val=`grep -i keepalive_timeout /etc/nginx/nginx.conf | xargs| cut -d' ' -f2| cut -d';' -f1`
		if [ $_val -gt 10 ] || [ $_val -eq 0 ];
		then
			echo -e "${ORANGE}${BOLD}Keepalive Time, 0 > keepalive_timeout <= 10 : ${RED}${UNN}FAIL${NC}"
			echo ""
			echo -e "${BLUE}Current Value ${IBlue}"
			grep -i keepalive_timeout /etc/nginx/nginx.conf | xargs
			echo ""
			echo -e "${ORANGE}${BOLD}Remediation${NC}"
			echo -e "${BLUE}Find the HTTP or server block of your nginx configuration, and add the keepalive_timeout
directive. Set it to 10 seconds or less, but not 0.${NC}"
		else
			#echo -e "${ORANGE}${BOLD}Keepalive Time, 0 > keepalive_timeout <= 10 : ${GREEN}PASS${NC}"
			echo -e "${ORANGE}${BOLD}NGINX keepalive_timeout variable set : ${GREEN}PASS${NC}"
			_secore_network=`expr $_secore_network + 1`
		fi
	else
		echo -e "${ORANGE}${BOLD}NGINX keepalive_timeout variable set : ${RED}${UNN}FAIL${NC}"
		echo ""
		echo -e "${ORANGE}${BOLD}Remediation${NC}"
		echo -e "${BLUE}Find the HTTP or server block of your nginx configuration, and add the keepalive_timeout
directive. Set it to 10 seconds or less, but not 0.${NC}"
                echo ""
                echo -e "${IBlue}keepalive_timeout 10;${NC}"
		echo ""
	fi

#--------------------------------------------NGNIX send_timeout variable set-------------------------------------------------------

        _status=`grep -i send_timeout /etc/nginx/nginx.conf | wc -l`

        if [ $_status -gt 0 ];
        then
		#echo ""
                #echo -e "${ORANGE}${BOLD}NGNIX send_timeout variable set : ${GREEN}PASS${NC}"
                #_val=`grep -i send_timeout /etc/nginx/nginx.conf | xargs| cut -d' ' -f2| cut -d';' -f1`
		_val=`grep -i send_timeout /etc/nginx/nginx.conf | xargs| cut -d' ' -f2| cut -d';' -f1 | cut -d'm' -f1`
                if [ $_val -gt 10 ] || [ $_val -eq 0 ];
                then
                        echo -e "${ORANGE}${BOLD}Send Time, 0 > send_timeout <= 10 : ${RED}${UNN}FAIL${NC}"
                        echo ""
                        echo -e "${BLUE}Current Value ${IBlue}"
                        grep -i send_timeout /etc/nginx/nginx.conf | xargs
                        echo ""
                        echo -e "${ORANGE}${BOLD}Remediation${NC}"
                        echo -e "${BLUE}Find the HTTP or server block of your nginx configuration, and add the send_timeout
directive. Set it to 10 seconds or less, but not 0.${NC}"
                else
                        #echo -e "${ORANGE}${BOLD}Send Time, 0 > send_timeout <= 10 : ${GREEN}PASS${NC}"
			echo -e "${ORANGE}${BOLD}NGNIX send_timeout variable set : ${GREEN}PASS${NC}"
			_secore_network=`expr $_secore_network + 1`
			echo ""
                fi
        else
		echo -e "${ORANGE}${BOLD}NGNIX send_timeout variable set : ${RED}${UNN}FAIL${NC}"
		echo ""
                echo -e "${ORANGE}${BOLD}Remediation${NC}"
                echo -e "${BLUE}Find the HTTP or server block of your nginx configuration, and add the send_timeout
directive. Set it to 10 seconds or less, but not 0.${NC}"
		echo ""
		echo -e "${IBlue}send_timeout 10;${NC}"
		echo ""
        fi
}

#--------------------------------------------------------------------------------------------------------------------------------------

function _check_nginx_information
{
	_title=`expr $_title + 1`

        echo -e "${IGreen}$_title.Information Disclosure${NC}"
        echo ""

	_status=`curl -sI 127.0.0.1 | grep -i server`

	if [[ $_status == *"/"* ]];
	then
		echo -e "${ORANGE}${BOLD}Hide NGINX version in server header : ${RED}${UNN}FAIL${NC}"
		echo ""
		echo -e "${BLUE}Current Value ${IBlue}"
		curl -sI 127.0.0.1 | grep -i server
		echo ""
		echo -e "${ORANGE}${BOLD}Remediation${NC}"
		echo -e "${BLUE}To disable the server_tokens directive, set it to off inside a server block in your nginx.conf.${NC}"
		echo ""
		echo -e "${IBlue}server_tokens off;${NC}"
		echo ""
	else
		echo -e "${ORANGE}${BOLD}Hide NGINX version in server header : ${GREEN}PASS${NC}"
		_secore_info=`expr $_secore_info + 1`
	fi

#---------------------------------------------------Removed default NGINX index.html and 50x.html----------------------------------------

	_status1=`grep -i nginx /usr/share/nginx/html/index.html 2> /dev/null | wc -l`
        _status2=`grep -i nginx /usr/share/nginx/html/50x.html 2> /dev/null | wc -l`

	if [ $_status1 -gt 0 ] || [ $_status2 -gt 0 ];
	then
		echo -e "${ORANGE}${BOLD}Removed default NGINX index.html and 50x.html : ${RED}${UNN}FAIL${NC}"
		echo ""
		echo -e "${ORANGE}${BOLD}Remediation${NC}"
		echo -e "${BLUE}Replace default index.html and 50x.html with your own files.${NC}"
		echo ""
	else
		echo -e "${ORANGE}${BOLD}Removed default NGINX index.html and 50x.html : ${GREEN}PASS${NC}"
		_secore_info=`expr $_secore_info + 1`
	fi

#-------------------------------------------------Nginx proxy_hide_header X-Powered-By set------------------------------------------------

	_status=`grep "proxy_hide_header X-Powered-By" /etc/nginx/nginx.conf | wc -l`

	if [ $_status -gt 0 ];
	then
		echo -e "${ORANGE}${BOLD}Nginx proxy_hide_header X-Powered-By set : ${GREEN}PASS${NC}"
		_secore_info=`expr $_secore_info + 1`
	else
		echo -e "${ORANGE}${BOLD}Nginx proxy_hide_header X-Powered-By set : ${RED}${UNN}FAIL${NC}"
		echo ""
		echo -e "${ORANGE}${BOLD}Remediation${NC}"
		echo -e "${BLUE}Implement the below directives as part of your location block. 
Edit /etc/nginx/nginx.conf and add the following.${NC}"
                echo ""
		echo -e "${IBlue}proxy_hide_header X-Powered-By;${NC}"
		echo ""
	fi

#-------------------------------------------------Nginx proxy_hide_header set--------------------------------------------------------------

        _status=`grep "proxy_hide_header Server" /etc/nginx/nginx.conf | wc -l`

        if [ $_status -gt 0 ];
        then
                echo -e "${ORANGE}${BOLD}Nginx proxy_hide_header set : ${GREEN}PASS${NC}"
		_secore_info=`expr $_secore_info + 1`
        else
                echo -e "${ORANGE}${BOLD}Nginx proxy_hide_header set : ${RED}${UNN}FAIL${NC}"
                echo ""
                echo -e "${ORANGE}${BOLD}Remediation${NC}"
                echo -e "${BLUE}Implement the below directives as part of your location block. 
Edit /etc/nginx/nginx.conf and add the following.${NC}"
                echo ""
                echo -e "${IBlue}proxy_hide_header Server;${NC}"
                echo ""
        fi
	
}

#-------------------------------------------------------------------------------------------------------------------------------------------

function _check_nginx_loggin
{
	_title=`expr $_title + 1`

	echo ""
        echo -e "${IGreen}$_title.NGINX Logging${NC}"
        echo ""

#----------------------------------------------------------Enable nginx access------------------------------------------------------------

	_status=`grep -ir "access_log off" /etc/nginx/ | grep -v "#" | wc -l`
	
	if [ $_status -gt 0 ];
	then
		echo -e "${ORANGE}${BOLD}Enable nginx access log : ${RED}${UNN}FAIL${NC}"
		echo ""
		echo -e "${BLUE}Detected Fiiles${NC}${IBlue}"
		grep -ir "access_log off" /etc/nginx/*
		echo ""
		echo -e "${ORANGE}${BOLD}Remediation${NC}"
		echo -e "${BLUE}Ensure the access_log directive is configured for every core site your organization requires
logging for.${NC}"
		echo ""
	else
		echo -e "${ORANGE}${BOLD}Enable nginx access log : ${GREEN}PASS${NC}"
		_secore_logging=`expr $_secore_logging + 1`
	fi

#-----------------------------------------------Enable nginx error log-----------------------------------------------------------------------

        _status=`grep error_log /etc/nginx/nginx.conf | grep -v "#" | wc -l`

        if [ $_status -gt 0 ];
        then
                echo -e "${ORANGE}${BOLD}Enable nginx error log  : ${GREEN}PASS${NC}"
		_secore_logging=`expr $_secore_logging + 1`
        else
                echo -e "${ORANGE}${BOLD}Enable nginx error log  : ${RED}${UNN}FAIL${NC}"
		echo ""
		echo -e "${ORANGE}${BOLD}Remediation${NC}"
		echo -e "${BLUE}Edit /etc/nginx/nginx.conf so the error_log directive is present and not commented out.
The error_log should be configured to the logging location of your choice. The configuration should look 
similar to the below${NC}"
		echo ""
		echo -e "${IBlue}error_log /var/log/nginx/error.log info;${NC}"
		echo ""
        fi

#------------------------------------------------------Nginx log rotation--------------------------------------------------------------------

	_status1=`cat /etc/logrotate.d/nginx| grep daily| wc -l`
	_status2=`cat /etc/logrotate.d/nginx| grep "rotate 7" | wc -l`
	_status3=`cat /etc/logrotate.d/nginx| grep "create 640 nginx root" | wc -l`

	if [ $_status1 -eq 0 ] || [ $_status2 -eq 0 ] || [ $_status3 -eq 0 ];
	then
		echo -e "${ORANGE}${BOLD}Nginx log rotation : ${RED}${UNN}FAIL${NC}"
		echo ""
		echo -e "${BLUE}Set logrotation parameters as follow in /etc/logrotate.d/nginx.${NC}"
		echo ""
		echo -e "${IBlue}/var/log/nginx/*.log {
        daily
        missingok
        rotate 7
        compress
        delaycompress
        notifempty
        create 640 nginx root
        sharedscripts
        postrotate
                if [ -f /var/run/nginx.pid ]; then
                        kill -USR1 `cat /var/run/nginx.pid`
                fi
        endscript
}${NC}"
	else
		echo -e "${ORANGE}${BOLD}Nginx log rotation : ${GREEN}PASS${NC}"
		_secore_logging=`expr $_secore_logging + 1`
	fi

#------------------------------------------------------------Client source IP hraders set-------------------------------------------------------

        _status1=`grep "proxy_set_header X-Real-IP" /etc/nginx/nginx.conf | grep -v "#" | wc -l`
	_status2=`grep "proxy_set_header X-Forwarded-For" /etc/nginx/nginx.conf | grep -v "#" | wc -l`

        if [ $_status1 -eq 0 ] || [ $_status2 -eq 0 ];
        then
                echo -e "${ORANGE}${BOLD}Client source IP hraders set : ${RED}${UNN}FAIL${NC}"
                echo ""
                echo -e "${ORANGE}${BOLD}Remediation${NC}"
                echo -e "${BLUE}To ensure your proxy or load balancer will forward information about the client and the
proxy to the application, you must set the below headers in your location block.${NC}"
                echo ""
                echo -e "${IBlue}proxy_set_header X-Real-IP \$remote_addr;${NC}"
		echo -e "${IBlue}proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;${NC}"
                echo ""
        else
                echo -e "${ORANGE}${BOLD}Client source IP hraders set : ${GREEN}PASS${NC}"
		_secore_logging=`expr $_secore_logging + 1`
	fi
}

#------------------------------------------------------------------------------------------------------------------------------------------------

function _check_nginx_ssl
{
	_title=`expr $_title + 1`

        echo ""
        echo -e "${IGreen}$_title.NGINX SSL Certificates${NC}"
        echo ""	

	#echo -e "${ORANGE}${BOLD}Private key permissions${NC}"
	#echo ""
	
	_conf_list=`grep -irw ssl_certificate_key /etc/nginx/conf.d/* | grep -v "#" | cut -d':' -f1`
	_conf_count=`grep -irw ssl_certificate_key /etc/nginx/conf.d/* | grep -v "#" | cut -d':' -f1| wc -l`
	_fail=0

	if [ $_conf_count == 0 ];
	then
		echo -e "${BLUE}No SSL Certificate files are detected for this NGINX server${NC}"
		echo ""
	else
	
		for ((j=1; j<=$_conf_count; j++));
		do
        		_conf_file=$(echo $_conf_list | cut -d' ' -f$j)
        		_key_file=`cat $_conf_file| grep ssl_certificate_key| xargs| cut -d' ' -f2 | cut -d';' -f1`
        		_permission=`stat --format '%a' $_key_file`

			if [ $_permission != 400 ];
			then
                                if [ $_fail == 0 ];
                                then
                                        echo -e "${ORANGE}${BOLD}Checking for Private key permissions${NC}"
                                        echo ""
                                fi
				echo -e "${IBlue}Key $_key_file doesn't have propper permission${NC}"
				_fail=1
			fi
		done	

		if [ $_fail == 1 ];
		then
			echo ""
			echo -e "${ORANGE}${BOLD}Private key permissions restricted : ${RED}${UNN}FAIL${NC}"
			echo ""
			echo -e "${ORANGE}${BOLD}Remediation${NC}"
			echo -e "${BLUE}Ensure private key permissions is set to 400. You can  use below command to make it right.${NC}"
			echo ""
			echo -e "${IBlue}chmod 400 <path to private key>${NC}"
			echo ""
			
		else
			echo -e "${ORANGE}${BOLD}Private key permissions restricted : ${GREEN}PASS${NC}"
			_secore_ssl=`expr $_secore_ssl + 1`
		fi
	fi

#------------------------------------------------------Enebled TLS protocol versions--------------------------------------------------------
	
	#echo ""
        #echo -e "${ORANGE}${BOLD}Enebled TLS protocol versions${NC}"
        #echo ""

        _conf_list=`grep -irwl ssl_protocols /etc/nginx/conf.d/*`
        _conf_count=`grep -irwl ssl_protocols /etc/nginx/conf.d/* | wc -l`
        _fail=0

        if [ $_conf_count == 0 ];
        then
                echo -e "${BLUE}No SSL Certificate files are detected for this NGINX server${NC}"
                echo ""
        else

                for ((j=1; j<=$_conf_count; j++));
                do
                        _conf_file=$(echo $_conf_list | cut -d' ' -f$j)
                        _ssl_protos=`cat $_conf_file| grep ssl_protocols| grep -v "#"| xargs`

			_tls1=`echo $_ssl_protos | grep -E "\TLSv1(\s|$)"|wc -l`
			_tls1_1=`echo $_ssl_protos | grep -E "\TLSv1.1(\s|$)"|wc -l`

                        if [ $_tls1 -gt 0 ] || [ $_tls1_1 -gt 0 ];
                        then
                                if [ $_fail == 0 ];
                                then
                                        echo -e "${ORANGE}${BOLD}Checking for Enebled TLS protocol versions${NC}"
                                        echo ""
                                fi
				echo -e "${BLUE}Config file $_conf_file has old TLS protocol${NC}"
				echo -e "${IBlue}Enable TLS Protocols : $_ssl_protos${NC}"
				echo ""
				_fail=1
                        fi
                done

                if [ $_fail == 1 ];
                then
                        echo -e "${ORANGE}${BOLD}Restricted old TLS protocols : ${RED}${UNN}FAIL${NC}"
                        echo ""
                        echo -e "${ORANGE}${BOLD}Remediation${NC}"
                        echo -e "${BLUE}Change your ssl_protocols if they are already configured with old TLS protocols.${NC}"
                        echo ""
                        echo -e "${IBlue}Keep Only TLS1.2 and TLS.1.3${NC}"
			echo ""
                    
                else
                        echo -e "${ORANGE}${BOLD}Restricted old TLS protocols : ${GREEN}PASS${NC}"
			_secore_ssl=`expr $_secore_ssl + 1`
                fi
        fi

#-----------------------------------------------------SSL Ciphers-----------------------------------------------------------

        _conf_list=`grep -irwl ssl_ciphers /etc/nginx/conf.d/*`
        _conf_count=`grep -irwl ssl_ciphers /etc/nginx/conf.d/* | wc -l`
        _fail=0

        if [ $_conf_count == 0 ];
        then
                echo -e "${BLUE}No SSL Certificate files are detected for this NGINX server${NC}"
                echo ""
        else

                for ((j=1; j<=$_conf_count; j++));
                do
                        _conf_file=$(echo $_conf_list | cut -d' ' -f$j)
                        _ssl_ciphers=`cat $_conf_file| grep -w ssl_ciphers | grep -v "#"| xargs`

                        _weak_cipher=`echo $_ssl_ciphers | grep ':MD5\|:DSS\|:aNULL\|:ADH\|:SSLv2\|:SSLv3\|:RC4\|:NULL\|:eNULL' | wc -l`

                        if [ $_weak_cipher -gt 0 ];
                        then
                                if [ $_fail == 0 ];
                                then
                                        echo -e "${ORANGE}${BOLD}Checking for Weak ciphers${NC}"
                                        echo ""
                                fi
                                echo -e "${BLUE}Config file $_conf_file has weak ciphers${NC}"
                                echo -e "${IBlue}Enable weak ciphers : $_ssl_ciphers${NC}"
                                echo ""
                                _fail=1
                        fi
                done

                if [ $_fail == 1 ];
                then
                        echo -e "${ORANGE}${BOLD}Restricted weak ciphers : ${RED}${UNN}FAIL${NC}"
                        echo ""
                        echo -e "${ORANGE}${BOLD}Remediation${NC}"
                        echo -e "${BLUE}Set the ssl_cipher directive as part of your server block, and set the proxy_ssl_ciphers
directive as part of the location block for your upstream server.${NC}"
                        echo ""
                        echo -e "${BLUE}Keep Only most secure cipher suite and disable rest.${NC}"
			echo -e "${IBlue}Ex: ssl_ciphers ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:RSA+AESGCM:!RSA+AES:!aNULL:!eNULL:!MD5:!DSS;${NC}"
                        echo ""

                else
                        echo -e "${ORANGE}${BOLD}Restricted weak ciphers : ${GREEN}PASS${NC}"
			_secore_ssl=`expr $_secore_ssl + 1`
                fi
        fi

#-----------------------------------------------------Diffie-Hellman parameter check----------------------------------------------------------------

	_status=`grep ssl_dhparam /etc/nginx/nginx.conf | wc -l`

	if [ $_status -eq 0 ];
	then
		echo -e "${ORANGE}${BOLD}Diffie-Hellman parameters set : ${RED}${UNN}FAIL${NC}"
		echo ""
		echo -e "${ORANGE}${BOLD}Remediation${NC}"
		echo -e "${BLUE}Generate strong DHE (Ephemeral Diffie-Hellman) parameters using the following commands.${NC}"
		echo ""
		echo -e "${IBlue}mkdir /etc/nginx/ssl"
		echo -e "${IBlue}openssl dhparam -out /etc/nginx/ssl/dhparam.key 2048"
		echo -e "${IBlue}chmod 400 /etc/nginx/ssl/dhparam.key${NC}"
		echo ""
		echo -e "${BLUE}Add ssl_dhparam /etc/nginx/ssl/dhparam.key; to nginx.conf file${NC}"
		echo ""
	else
		echo -e "${ORANGE}${BOLD}Diffie-Hellman parameters set : ${GREEN}PASS${NC}"
		_secore_ssl=`expr $_secore_ssl + 1`
	fi 

#-----------------------------------------------------Strict-Transport-Security--------------------------------------------------------------------

        #echo ""
        #echo -e "${ORANGE}${BOLD}HTTP STS Hraders${NC}"
        #echo ""

        #_conf_list=`grep -irw ssl_certificate /etc/nginx/conf.d/* | grep -v "#" | cut -d':' -f1`
        #_conf_count=`grep -irw ssl_certificate /etc/nginx/conf.d/* | grep -v "#" | cut -d':' -f1 | wc -l`
	_conf_list=`grep -irwl ssl_certificate /etc/nginx/conf.d/*`
	_conf_count=`grep -irwl ssl_certificate /etc/nginx/conf.d/* | wc -l`
        _fail=0

        if [ $_conf_count == 0 ];
        then
                echo -e "${BLUE}No SSL enable config files are avalaibe for this NGINX server${NC}"
                echo ""
        else

                for ((j=1; j<=$_conf_count; j++));
                do
                        _conf_file=$(echo $_conf_list | cut -d' ' -f$j)
                        _ssl_sts=`cat $_conf_file | grep -v "#" | grep -c Strict-Transport-Security| xargs`

                        if [ $_ssl_sts -eq 0 ];
                        then
				if [ $_fail == 0 ];
				then
        				echo -e "${ORANGE}${BOLD}Checking for HTTP STS Hraders${NC}"
        				echo ""
				fi
                                echo -e "${BLUE}Config file $_conf_file has no HTTP STS configuration${NC}"
                                echo ""
                                _fail=1
                        fi
                done

                if [ $_fail == 1 ];
                then
                        echo -e "${ORANGE}${BOLD}HTTP STS headers set : ${RED}${UNN}FAIL${NC}"
                        echo ""
                        echo -e "${ORANGE}${BOLD}Remediation${NC}"
                        echo -e "${BLUE}Ensure the below snippet of code can be found in your server configuration for your proxy
or web server. This will ensure the HSTS header is set with a validity period of six months, or 15768000 seconds.${NC}"
                        echo ""
                        echo -e "${IBlue}Add this. add_header Strict-Transport-Security \"max-age=15768000;\"${NC}"
                else
                        echo -e "${ORANGE}${BOLD}HTTP STS headers set : ${GREEN}PASS${NC}"
			_secore_ssl=`expr $_secore_ssl + 1`
                fi
        fi

#---------------------------------------------------------Session resumption is disabled----------------------------------------------------

        _status=`grep ssl_session_tickets /etc/nginx/nginx.conf | wc -l`

        if [ $_status -eq 0 ];
        then
                echo -e "${ORANGE}${BOLD}Session resumption is disabled : ${RED}${UNN}FAIL${NC}"
                echo ""
                echo -e "${ORANGE}${BOLD}Remediation${NC}"
                echo -e "${BLUE}Turn off the ssl_session_tickets directive as part of any server block in your nginx configuration:${NC}"
                echo ""
		echo -e "${BLUE}Add below parameter to /etc/nginx/nginx.conf file.${NC}"
                echo -e "${IBlue}ssl_session_tickets off;${NC}"
        else
                echo -e "${ORANGE}${BOLD}Session resumption is disabled : ${GREEN}PASS${NC}"
		_secore_ssl=`expr $_secore_ssl + 1`
        fi
}

#------------------------------------------------------------------------------------------------------------------------------------------

function _check_nginx_request_limit
{
	_title=`expr $_title + 1`

        echo ""
        echo -e "${IGreen}$_title.NGINX Request Limit${NC}"
        echo ""

#---------------------------------------------------Client header and body timeout set-----------------------------------------------------

	_status1=`grep -i client_body_timeout /etc/nginx/nginx.conf | wc -l`
        _status2=`grep -i client_header_timeout /etc/nginx/nginx.conf | wc -l`

	if [ $_status1 -gt 0 ] || [ $_status2 -gt 0 ];
	then
		echo -e "${ORANGE}${BOLD}Client header and body timeout set : ${GREEN}PASS${NC}"
		_secore_limit=`expr $_secore_limit + 1`
	else
		echo -e "${ORANGE}${BOLD}Client header and body timeout set : ${RED}${UNN}FAIL${NC}"
		echo ""
		echo -e "${ORANGE}${BOLD}Remediation${NC}"
		echo -e "${BLUE}Find the HTTP or server block of your nginx configuration and add the client_header_timeout 
and client_body_timeout directives set to the configuration. The below example sets the timeouts to 10 seconds.${NC}"
		echo ""
		echo -e "${IBlue}client_body_timeout 10;"
		echo -e "${IBlue}client_header_timeout 10;${NC}"
		echo ""
	fi	

#---------------------------------------------------Client max body size set----------------------------------------------------------------

        _status=`grep -i client_max_body_size /etc/nginx/nginx.conf | wc -l`

        if [ $_status -gt 0 ];
        then
                echo -e "${ORANGE}${BOLD}Client max body size set : ${GREEN}PASS${NC}"
		_secore_limit=`expr $_secore_limit + 1`
        else
                echo -e "${ORANGE}${BOLD}Client max body size set : ${RED}${UNN}FAIL${NC}"
                echo ""
                echo -e "${ORANGE}${BOLD}Remediation${NC}"
                echo -e "${BLUE}Find the HTTP or server block of your nginx configuration and add the client_max_body_size 
set to 100K in this block. The appropriate value may be different based on your application's needs.${NC}"
                echo ""
                echo -e "${IBlue}client_max_body_size 100K;${NC}"
                echo ""
        fi

#---------------------------------------------------Client max buffer size set---------------------------------------------------------------

        _status=`grep -i large_client_header_buffers /etc/nginx/nginx.conf | wc -l`

        if [ $_status -gt 0 ];
        then
                echo -e "${ORANGE}${BOLD}Client max buffer size set : ${GREEN}PASS${NC}"
		_secore_limit=`expr $_secore_limit + 1`
        else
                echo -e "${ORANGE}${BOLD}Client max buffer size set : ${RED}${UNN}FAIL${NC}"
                echo ""
                echo -e "${ORANGE}${BOLD}Remediation${NC}"
                echo -e "${BLUE}Open your nginx.conf file and locate your server or HTTP blocks. This may be added to the HTTP block for all 
configurations or the server block for more specific configurations tomeet your needs. Add the below line to implement this recommendation.${NC}"
                echo ""
                echo -e "${IBlue}large_client_header_buffers 2 1k;${NC}"
                echo ""
        fi

#-----------------------------------------------------Limit max num of simultaneous connections-----------------------------------------------

        _status=`grep -i "limit_conn_zone" /etc/nginx/nginx.conf | wc -l`

        if [ $_status -gt 0 ];
        then
                echo -e "${ORANGE}${BOLD}Limit max num of simultaneous connections per client : ${GREEN}PASS${NC}"
		_secore_limit=`expr $_secore_limit + 1`
        else
                echo -e "${ORANGE}${BOLD}Limit max num of simultaneous connections per client : ${RED}${UNN}FAIL${NC}"
                echo ""
                echo -e "${ORANGE}${BOLD}Remediation${NC}"
                echo -e "${BLUE}Implement the below directives under the HTTP and server blocks of your nginx configuration 
or any include files. The below configuration creates a memory zone of 10 megabytes called limitperip. It will limit the
number of connections per IP address to 10 simultaneous connections. The number of simultaneous connections to allow may be
different depending on your organization's policies and use cases.${NC}"
                echo ""
                echo -e "${IBlue}http {
	limit_conn_zone \$binary_remote_addr zone=limitperip:10m;
	server {
		limit_conn limitperip 10;
	}
};${NC}"
                #echo ""
        fi
}

#-----------------------------------------------------------------------------------------------------------------------------------------------

function _check_nginx_browser_sec
{
	_title=`expr $_title + 1`
        echo ""
        echo -e "${IGreen}$_title.Browser Security${NC}"
        echo ""

#------------------------------------------------------X-Frame-Options--------------------------------------------------------------------------

        _conf_list=`grep -irwl server_name /etc/nginx/conf.d/*`
        _conf_count=`grep -irwl server_name /etc/nginx/conf.d/* | wc -l`
        _fail=0

        for ((j=1; j<=$_conf_count; j++));
        do
                 _conf_file=$(echo $_conf_list | cut -d' ' -f$j)
                 _x_frame=`cat $_conf_file | grep -v "#" | grep -c X-Frame-Options | xargs`

                 if [ $_x_frame -eq 0 ];
                 then
                        if [ $_fail == 0 ];
                        then
                                echo -e "${ORANGE}${BOLD}Checking for X-Frame-Options Hraders${NC}"
                                echo ""
                        fi
                        echo -e "${BLUE}Config file $_conf_file has no X-Frame-Options${NC}"
                        _fail=1
                 fi
         done

         if [ $_fail == 1 ];
         then
                echo ""
                echo -e "${ORANGE}${BOLD}X-Frame-Options header set : ${RED}${UNN}FAIL${NC}"
                echo ""
                echo -e "${ORANGE}${BOLD}Remediation${NC}"
                echo -e "${BLUE}Add the below to your server blocks in your nginx configuration. The policy should be
configured to meet your organization's needs.${NC}"
                echo ""
                echo -e "${IBlue}Add this. add_header X-Frame-Options \"SAMEORIGIN\";${NC}"
                echo ""
         else
                echo -e "${ORANGE}${BOLD}X-Frame-Options header set : ${GREEN}PASS${NC}"
		_secore_browser=`expr $_secore_browser + 1`
         fi

#------------------------------------------------X-Content-Type-Options-------------------------------------------------------------------------

        _conf_list=`grep -irwl server_name /etc/nginx/conf.d/*`
        _conf_count=`grep -irwl server_name /etc/nginx/conf.d/* | wc -l`
        _fail=0

        for ((j=1; j<=$_conf_count; j++));
        do
                 _conf_file=$(echo $_conf_list | cut -d' ' -f$j)
                 _x_content=`cat $_conf_file | grep -v "#" | grep -c X-Content-Type-Options | xargs`

                 if [ $_x_content -eq 0 ];
                 then
                        if [ $_fail == 0 ];
                        then
                                echo -e "${ORANGE}${BOLD}Checking for X-Content-Type-Options Hraders${NC}"
                                echo ""
                        fi
                        echo -e "${BLUE}Config file $_conf_file has no X-Content-Type-Options${NC}"
                        _fail=1
                 fi
         done

         if [ $_fail == 1 ];
         then
                echo ""
                echo -e "${ORANGE}${BOLD}X-Content-Type-Options header set : ${RED}${UNN}FAIL${NC}"
                echo ""
                echo -e "${ORANGE}${BOLD}Remediation${NC}"
                echo -e "${BLUE}Open the nginx configuration file that contains your server blocks. Add the below line into
your server block to add X-Content-Type-Options header and direct your user agent to not sniff content types.${NC}"
                echo ""
                echo -e "${IBlue}Add this. add_header X-Content-Type-Options \"nosniff\";${NC}"
                echo ""
         else
                echo -e "${ORANGE}${BOLD}X-Content-Type-Options header set : ${GREEN}PASS${NC}"
		_secore_browser=`expr $_secore_browser + 1`
         fi

#------------------------------------------------------X-Xss-Protection---------------------------------------------------------------------------

        _conf_list=`grep -irwl server_name /etc/nginx/conf.d/*`
        _conf_count=`grep -irwl server_name /etc/nginx/conf.d/* | wc -l`
        _fail=0

        for ((j=1; j<=$_conf_count; j++));
        do
                 _conf_file=$(echo $_conf_list | cut -d' ' -f$j)
                 _x_content=`cat $_conf_file | grep -v "#" | grep -c X-XSS-Protection | xargs`

                 if [ $_x_content -eq 0 ];
                 then
                        if [ $_fail == 0 ];
                        then
                                echo -e "${ORANGE}${BOLD}Checking for X-XSS-Protection Hraders${NC}"
                                echo ""
                        fi
                        echo -e "${BLUE}Config file $_conf_file has no X-XSS-Protection${NC}"
                        _fail=1
                 fi
         done

         if [ $_fail == 1 ];
         then
                echo ""
                echo -e "${ORANGE}${BOLD}X-Xss-Protection header set : ${RED}${UNN}FAIL${NC}"
                echo ""
                echo -e "${ORANGE}${BOLD}Remediation${NC}"
                echo -e "${BLUE}Open your nginx configuration file that contains your server blocks. Add the below line into
your server block to add Content-Security-Policy and direct your user agent to block reflected cross-site scripting.${NC}"
                echo ""
                echo -e "${IBlue}Add this. add_header X-Xss-Protection \"1; mode=block\";${NC}"
                echo ""
         else
                echo -e "${ORANGE}${BOLD}X-Xss-Protection header set : ${GREEN}PASS${NC}"
		_secore_browser=`expr $_secore_browser + 1`
         fi

#------------------------------------------------Content-Security-Policy-----------------------------------------------------------------------------

        _conf_list=`grep -irwl server_name /etc/nginx/conf.d/*`
        _conf_count=`grep -irwl server_name /etc/nginx/conf.d/* | wc -l`
        _fail=0

        for ((j=1; j<=$_conf_count; j++));
        do
                 _conf_file=$(echo $_conf_list | cut -d' ' -f$j)
                 _x_content=`cat $_conf_file | grep -v "#" | grep -c Content-Security-Policy | xargs`

                 if [ $_x_content -eq 0 ];
                 then
                        if [ $_fail == 0 ];
                        then
                                echo -e "${ORANGE}${BOLD}Checking for Content-Security-Policy Hraders${NC}"
                                echo ""
                        fi
                        echo -e "${BLUE}Config file $_conf_file has no Content-Security-Policy${NC}"
                        _fail=1
                 fi
         done

         if [ $_fail == 1 ];
         then
                echo ""
                echo -e "${ORANGE}${BOLD}Content-Security-Policy header set : ${RED}${UNN}FAIL${NC}"
                echo ""
                echo -e "${ORANGE}${BOLD}Remediation${NC}"
                echo -e "${BLUE}Open the nginx configuration file that contains your server blocks. Add the below line into
your server block to add X-Content-Type-Options header and direct your user agent to not sniff content types..${NC}"
                echo ""
                echo -e "${IBlue}Add this. add_header Content-Security-Policy \"default-src 'self'\";${NC}"
                echo ""
         else
                echo -e "${ORANGE}${BOLD}Content-Security-Policy header set : ${GREEN}PASS${NC}"
		_secore_browser=`expr $_secore_browser + 1`
         fi

#--------------------------------------------------------Referrer-Policy---------------------------------------------------------------------

        _conf_list=`grep -irwl server_name /etc/nginx/conf.d/*`
        _conf_count=`grep -irwl server_name /etc/nginx/conf.d/* | wc -l`
        _fail=0

        for ((j=1; j<=$_conf_count; j++));
        do
                 _conf_file=$(echo $_conf_list | cut -d' ' -f$j)
                 _x_content=`cat $_conf_file | grep -v "#" | grep -c Referrer-Policy | xargs`

                 if [ $_x_content -eq 0 ];
                 then
                        if [ $_fail == 0 ];
                        then
                                echo -e "${ORANGE}${BOLD}Checking for Referrer-Policy Hraders${NC}"
                                echo ""
                        fi
                        echo -e "${BLUE}Config file $_conf_file has no Referrer-Policy${NC}"
                        _fail=1
                 fi
         done

         if [ $_fail == 1 ];
         then
                echo ""
                echo -e "${ORANGE}${BOLD}Referrer-Policy header set : ${RED}${UNN}FAIL${NC}"
                echo ""
                echo -e "${ORANGE}${BOLD}Remediation${NC}"
                echo -e "${BLUE}Add the below line to the server blocks within your nginx configuration. The policy should be customized 
for your specific organization's needs. The below policy will ensure your website is never allowed in a referrer.${NC}"
                echo ""
                echo -e "${IBlue}Add this. add_header Referrer-Policy \"no-referrer\";${NC}"
                echo ""
         else
                echo -e "${ORANGE}${BOLD}Referrer-Policy header set : ${GREEN}PASS${NC}"
		_secore_browser=`expr $_secore_browser + 1`
         fi
}

#-------------------------------------------------------------------------------------------------------------------------------------------

function _print_results
{

	_secore=`expr $_secore_module + $_secore_security + $_secore_ownership + $_secore_network + $_secore_info + $_secore_logging + $_secore_ssl + $_secore_limit + $_secore_browser`

        echo " "
        echo " "
        tput rev
        echo -e "${YELLOW}##################################################"
        echo -e "${YELLOW}#                                                #"
        echo -e "${YELLOW}#           NGINX BENCHMARK RESULTS              #"
        echo -e "${YELLOW}#                                                #"
        echo -e "${YELLOW}##################################################${NC}"
        tput sgr0
        echo " "
        echo " "
	echo -e "${YELLOW}NGINX Version      : ${GREEN}$nginx_version${NC}"
	echo -e "${YELLOW}System Information : ${GREEN}$(uname -smo)${NC}"
	echo ""
	echo -e "${RED}Benchmark Results${NC}"
	echo ""
        echo -e "\t${YELLOW}Minimize NGINX Modules\t\t:${GREEN} [${RED}$_secore_module/3${GREEN}]${NC}"
        echo -e "\t${YELLOW}Nginx Account Security\t\t:${GREEN} [${RED}$_secore_security/5${GREEN}]${NC}"
        echo -e "\t${YELLOW}Permissions and Ownership\t:${GREEN} [${RED}$_secore_ownership/6${GREEN}]${NC}"
        echo -e "\t${YELLOW}Network Configurations\t\t:${GREEN} [${RED}$_secore_network/3${GREEN}]${NC}"
        echo -e "\t${YELLOW}Information Disclosure\t\t:${GREEN} [${RED}$_secore_info/4${GREEN}]${NC}"
        echo -e "\t${YELLOW}NGINX Logging\t\t\t:${GREEN} [${RED}$_secore_logging/4${GREEN}]${NC}"
        echo -e "\t${YELLOW}NGINX SSL Certificates\t\t:${GREEN} [${RED}$_secore_ssl/6${GREEN}]${NC}"
        echo -e "\t${YELLOW}NGINX Request Limit\t\t:${GREEN} [${RED}$_secore_limit/4${GREEN}]${NC}"
        echo -e "\t${YELLOW}Browser Security\t\t:${GREEN} [${RED}$_secore_browser/5${GREEN}]${NC}"
	echo ""
	echo -e "${RED}Total Score\t:${GREEN} [${UNN}${YELLOW}$_secore${NC}/${YELLOW}40${GREEN}]${NC}"
	echo ""

}

#-------------------------------------------------------------------------------------------------------------------------------------------

function _print_list
{
	echo -e "\t${YELLOW}ALL\t\t\t\t:${GREEN} 1${NC}"
	echo -e "\t${YELLOW}Minimize NGINX Modules\t\t:${GREEN} 2${NC}"
	echo -e "\t${YELLOW}Nginx Account Security\t\t:${GREEN} 3${NC}"
	echo -e "\t${YELLOW}Permissions and Ownership\t:${GREEN} 4${NC}"
	echo -e "\t${YELLOW}Network Configurations\t\t:${GREEN} 5${NC}"
	echo -e "\t${YELLOW}Information Disclosure\t\t:${GREEN} 6${NC}"
	echo -e "\t${YELLOW}NGINX Logging\t\t\t:${GREEN} 7${NC}"
	echo -e "\t${YELLOW}NGINX SSL Certificates\t\t:${GREEN} 8${NC}"
	echo -e "\t${YELLOW}NGINX Request Limit\t\t:${GREEN} 9${NC}"
	echo -e "\t${YELLOW}Browser Security\t\t:${GREEN} 10${NC}"
	echo ""
}

echo ""

_print_banner
_print_list

nginx_version=$(nginx -v 2>&1)
nginx_version=`echo $nginx_version| cut -d':' -f2| xargs`

echo -e -n "${D_RED}Select Your Option: ${NC} " ; read _option_id
echo ""

if [ $_option_id -eq 1 ];
then
	_check_dev_module
	_check_gzip_module
	_check_auto_index
	_check_nginx_user
	_check_file_ownerwhip
	_check_file_permission
	_check_nginx_pid_file
	_check_nginx_network
	_check_nginx_information
	_check_nginx_loggin
	_check_nginx_ssl
	_check_nginx_request_limit
	_check_nginx_browser_sec
elif [ $_option_id -eq 2 ];
then
	_check_dev_module
	_check_gzip_module
	_check_auto_index
elif [ $_option_id -eq 3 ];
then
	_check_nginx_user
elif [ $_option_id -eq 4 ];
then
	_check_file_ownerwhip
	_check_file_permission
	_check_nginx_pid_file
elif [ $_option_id -eq 5 ];
then
	_check_nginx_network
elif [ $_option_id -eq 6 ];
then
	_check_nginx_information
elif [ $_option_id -eq 7 ];
then
	_check_nginx_loggin
elif [ $_option_id -eq 8 ];
then
	_check_nginx_ssl
elif [ $_option_id -eq 9 ];
then
	_check_nginx_request_limit
elif [ $_option_id -eq 10 ];
then
	_check_nginx_browser_sec
else
	"[Error] Wrong Input"
	exit 99
fi

_print_results

