#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <netdb.h>
#include <getopt.h>
#include <ctype.h>
#include <xtables.h>

#include <linux/netfilter/xt_dnp3.h>


enum {
    O_CHECKSUM = 0,
    O_DADDR,
    O_SADDR,
    O_FC,
};

static const struct option dnp3_opts[] = {
        { .name = "chksum", .has_arg = false, .val = O_CHECKSUM },
        { .name = "daddr", .has_arg = true, .val = O_DADDR },
        { .name = "destination-addr", .has_arg = true, .val = O_DADDR },
        { .name = "fc", .has_arg = true, .val = O_FC },
        { .name = "function-code", .has_arg = true, .val = O_FC },
        { .name = "saddr", .has_arg = true, .val = O_SADDR },
        { .name = "source-addr", .has_arg = true, .val = O_SADDR },
        XT_GETOPT_TABLEEND,
};


static void dnp3_help( void );

static void dnp3_init( struct xt_entry_match *m );

static int dnp3_parse( int c, char **argv, int invert, unsigned int *flags, const void *entry, struct xt_entry_match **match );

static void dnp3_parse_address( const char *arg, uint16_t *addr );

static void dnp3_parse_function( const char *arg, uint8_t *func );

static int dnp3_parse_isnumber( const char *arg );

static void dnp3_print( const void *ip, const struct xt_entry_match *match, int numeric );

static void dnp3_output_address( const char *name, uint16_t min, uint16_t max, int invert, int flag );

static void dnp3_output_function( const char *name, uint8_t *func, int invert, int flag );

static void dnp3_save( const void *ip, const struct xt_entry_match *match ); 


static void 
dnp3_help( void ) 
{
    printf(
"dnp3 match options:\n"
"[!] --destination-addr address[:address]\n"
" --daddr ...\n"
"\t\t\t\tdestination address(es)\n"
"[!] --source-addr address[:address]\n"
" --saddr ...\n"
"\t\t\t\tsource address(es)\n" 
"[!] --function-code code[,code]\n"
" --fc ...\n"
"\t\t\t\tfunction code(s)\n");
}


static void 
dnp3_init( struct xt_entry_match *m )
{
    struct xt_dnp3 *dnp3info = (struct xt_dnp3 *) m->data;

    ( void ) memset( dnp3info, 0, sizeof( *dnp3info ) );
    dnp3info->daddr[1] = dnp3info->saddr[1]
            = (uint16_t) ~0U;
    dnp3info->set = dnp3info->invert = 0;
}


static int
dnp3_parse( int c, char **argv, int invert, unsigned int *flags, const void *entry, struct xt_entry_match **match )
{
    struct xt_dnp3 *dnp3info = ( struct xt_dnp3 * ) (*match)->data;
    uint8_t flag;

    flag = 0;
    switch( c ) {
        case O_CHECKSUM:
            flag = XT_DNP3_FLAG_CHECKSUM;
            break;
        case O_DADDR:
            if( *flags & XT_DNP3_FLAG_DADDR ) {
                xtables_error( PARAMETER_PROBLEM, 
                        "Only single `--destination-addr` definition allowed" );
            }
            dnp3_parse_address( optarg, dnp3info->daddr );
            flag = XT_DNP3_FLAG_DADDR;
            break;
        case O_SADDR:
            if( *flags & XT_DNP3_FLAG_SADDR ) {
                xtables_error( PARAMETER_PROBLEM, 
                        "Only single `--source-addr` definition allowed" );
            }
            dnp3_parse_address( optarg, dnp3info->saddr );
            flag = XT_DNP3_FLAG_SADDR;
            break;
        case O_FC:
            if( ( *flags & XT_DNP3_FLAG_FC ) &&
                    ( ( dnp3info->invert & XT_DNP3_FLAG_FC ) || 
                            invert ) ) {
                xtables_error( PARAMETER_PROBLEM, 
                        "Only single `--function-code` definition allowed with inversion" );
            }
            dnp3_parse_function( optarg, dnp3info->fc );
            flag = XT_DNP3_FLAG_FC;
            break;
    }
    if( invert ) {
        dnp3info->invert |= flag;
    }
    dnp3info->set |= flag;
    *flags |= flag;

    return 1;
}


static void
dnp3_parse_address( const char *arg, uint16_t *addr )
{
    char *buffer, *ptr;

    buffer = strdup( arg );
    if( ( ptr = strchr( buffer, ':' ) ) == NULL ) {
        addr[0] = addr[1] = xtables_parse_port( buffer, NULL );
    }
    else {
        *ptr++ = '\0';

        addr[0] = buffer[0] ? xtables_parse_port( buffer, NULL ) : 0;
        addr[1] = ptr[0] ? xtables_parse_port( ptr, NULL ) : 0xffff;
        if( addr[0] > addr[1] ) {
            xtables_error( PARAMETER_PROBLEM,
                    "Invalid DNP3 address range (min > max)" );
        }
    }
    free( buffer );
}


static void
dnp3_parse_function( const char *arg, uint8_t *func )
{
    char *buffer, *ptr;
    uint8_t val;

    buffer = strdup( arg );
    for( ptr = strtok( buffer, "," );
            ptr;
            ptr = strtok( NULL, "," ) ) {

        if( dnp3_parse_isnumber( ptr ) == 0 ) {
            xtables_error( PARAMETER_PROBLEM,
                    "Only numeric DNP3 function codes accepted" );
        }
        val = ( uint8_t ) strtoul( ptr, NULL, 10 );
        func[ val / 8 ] |= ( 1 << ( val % 8 ) );
    }
    free( buffer );
}


static int 
dnp3_parse_isnumber( const char *arg )
{
    if( arg == NULL ) {
        return 0;
    }
    while( *arg ) {
        if( isdigit( *arg++ ) == 0 ) {
            return 0;
        }
    }
    return 1;
}


static void
dnp3_print( const void *ip, const struct xt_entry_match *match, int numeric )
{
    struct xt_dnp3 *dnp3info = (struct xt_dnp3 *) match->data;

    printf( " dnp3" );

    printf( "%s%s",
            ( dnp3info->invert & XT_DNP3_FLAG_CHECKSUM ) ? " !" : "",
            ( dnp3info->set & XT_DNP3_FLAG_CHECKSUM ) ? " chksum" : "" );

    dnp3_output_address( "daddr",
            dnp3info->daddr[0],
            dnp3info->daddr[1],
            dnp3info->invert & XT_DNP3_FLAG_DADDR,
            dnp3info->set & XT_DNP3_FLAG_DADDR );
    dnp3_output_address( "saddr",
            dnp3info->saddr[0],
            dnp3info->saddr[1],
            dnp3info->invert & XT_DNP3_FLAG_SADDR,
            dnp3info->set & XT_DNP3_FLAG_SADDR );
    dnp3_output_function( "fc",
            dnp3info->fc,
            dnp3info->invert & XT_DNP3_FLAG_FC,
            dnp3info->set & XT_DNP3_FLAG_FC );
}


static void
dnp3_output_address( const char *name, uint16_t min, uint16_t max, int invert, int flag )
{
    if( ! flag ) {
        return;
    }

    printf( " %s%s ", invert ? "! " : "", name );
    if( min != max ) {
        printf( "%u:%u",
                min,
                max ); 
    }
    else {
        printf( "%u", min );
    }
}

static void
dnp3_output_function( const char *name, uint8_t *func, int invert, int flag ) 
{
    uint8_t bit, byte, count;

    if( ! flag ) {
        return;
    }

    printf( " %s%s ", invert ? "! " : "", name );

    count = 0;
    for( byte = 0; byte < 32; ++byte ) {
        if( func[ byte ] == 0 ) {
            continue;
        }
        for( bit = 0; bit < 8; ++bit ) {
            if( ( func[ byte ] & ( 1 << bit ) ) != 0 ) {
                printf( "%s%u", ( ++count > 1 ) ? "," : "", ( ( 8 * byte ) + bit ) );
            }
        }
    }
}


static void 
dnp3_save( const void *ip, const struct xt_entry_match *match )
{
    struct xt_dnp3 *dnp3info = (struct xt_dnp3 *) match->data;

    printf( "%s%s", 
            ( dnp3info->invert & XT_DNP3_FLAG_CHECKSUM ) ? "! " : "",
            ( dnp3info->set & XT_DNP3_FLAG_CHECKSUM ) ? "--chksum" : "" );

    dnp3_output_address( "--daddr",
            dnp3info->daddr[0],
            dnp3info->daddr[0],
            dnp3info->invert & XT_DNP3_FLAG_DADDR,
            dnp3info->set & XT_DNP3_FLAG_DADDR );
    dnp3_output_address( "--saddr",
            dnp3info->saddr[0],
            dnp3info->saddr[0],
            dnp3info->invert & XT_DNP3_FLAG_SADDR,
            dnp3info->set & XT_DNP3_FLAG_SADDR );
    dnp3_output_function( "--fc",
            dnp3info->fc,
            dnp3info->invert & XT_DNP3_FLAG_FC,
            dnp3info->set & XT_DNP3_FLAG_FC );
}


static struct xtables_match dnp3_match = {
    .family             = NFPROTO_UNSPEC,
    .name               = "dnp3",
    .version            = XTABLES_VERSION,
    .size               = XT_ALIGN( sizeof( struct xt_dnp3 ) ),
    .userspacesize      = XT_ALIGN( sizeof( struct xt_dnp3 ) ),
    .help               = dnp3_help,
    .init               = dnp3_init,
    .parse              = dnp3_parse,
    .print              = dnp3_print,
    .save               = dnp3_save,
    .extra_opts         = dnp3_opts,
};


void
_init( void) 
{
    xtables_register_match( &dnp3_match );
}
