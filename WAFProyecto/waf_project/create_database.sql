/* ============================================================ */
/* base de datos: sentinel_waf                                  */
/* motor: innodb                                                */
/* descripcion: sistema waf (web application firewall)          */
/*              con logging, alertas, bloqueo de ips,           */
/*              auditoria, funciones, procedimientos,           */
/*              triggers y control de acceso por roles.         */
/* ============================================================ */

create database sentinel_waf;
use sentinel_waf;

/* ============================================================ */
/*  DDL – CREACION DE TABLAS                                    */
/* ============================================================ */

/* tabla de tipos de ataque (catalogo normalizado) */
create table tipos_ataque (
  id_ataque    int          not null auto_increment,
  nombre       varchar(50)  not null,
  descripcion  varchar(255) null,
  nivel_riesgo_base int     not null default 0,
  primary key (id_ataque)
) engine=innodb;

/* tabla de ips bloqueadas */
create table ips_bloqueadas (
  ip_address       varchar(45)  not null,
  motivo           varchar(255) null,
  fecha_bloqueo    datetime     not null,
  fecha_expiracion datetime     null,
  activa           boolean      not null default 1,
  primary key (ip_address)
) engine=innodb;

/* tabla de log de peticiones */
create table peticiones_log (
  id_log         int          not null auto_increment,
  fecha_hora     datetime     not null,
  ip_address     varchar(45)  not null,
  metodo         varchar(10)  not null,
  endpoint       varchar(255) not null,
  user_agent     varchar(255) null,
  score_riesgo   int          not null default 0,
  accion_tomada  varchar(20)  null,
  id_ataque      int          null,
  primary key (id_log),
  foreign key (id_ataque) references tipos_ataque(id_ataque)
    on delete cascade on update cascade
) engine=innodb;

/* tabla de alertas */
create table alertas (
  id_alerta        int          not null auto_increment,
  id_log           int          not null,
  nivel_criticidad varchar(20)  null,
  mensaje          varchar(255) null,
  revisada         boolean      not null default 0,
  fecha_generacion datetime     not null,
  primary key (id_alerta),
  foreign key (id_log) references peticiones_log(id_log)
    on delete cascade on update cascade
) engine=innodb;

/* tabla de auditoria del sistema */
create table auditoria_sistema (
  id_auditoria   int          not null auto_increment,
  tabla_afectada varchar(50)  not null,
  accion         varchar(50)  not null,
  detalle_cambio varchar(255) null,
  fecha_hora     datetime     not null,
  usuario_db     varchar(50)  null,
  primary key (id_auditoria)
) engine=innodb;

-- Script para añadir la tabla de 'clientes' requerida por Sentinel Agent SDK
CREATE TABLE IF NOT EXISTS clientes (
    client_id VARCHAR(50) PRIMARY KEY,
    api_key VARCHAR(100) NOT NULL UNIQUE,
    nombre_empresa VARCHAR(150) NOT NULL,
    target_url VARCHAR(255) DEFAULT NULL,
    plan VARCHAR(50) DEFAULT 'basico',
    activo BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insertar un cliente de prueba (Demo Client)
INSERT INTO clientes (client_id, api_key, nombre_empresa, target_url, plan)
VALUES (
    'demo-client-id-001',
    'sk_test_sentinel_123456789',
    'Escuela Demo SA de CV',
    'http://localhost:3000',
    'enterprise'
) ON DUPLICATE KEY UPDATE activo=1;


/* ============================================================ */
/*  OBJETOS PROGRAMABLES – FUNCIONES                            */
/* ============================================================ */

delimiter //

create function fn_evaluar_criticidad(in_score int)
returns varchar(20)
reads sql data
begin
  declare v_resultado varchar(20);

  if in_score < 40 then
    set v_resultado = 'Info';
  elseif in_score >= 40 and in_score < 70 then
    set v_resultado = 'Advertencia';
  else
    set v_resultado = 'Critico';
  end if;

  return v_resultado;
end//

delimiter ;

delimiter //

create function fn_estado_bloqueo_ip(in_ip varchar(45))
returns int
reads sql data
begin
  declare v_existe int default 0;

  select count(*)
  into v_existe
  from ips_bloqueadas
  where ip_address = in_ip
    and activa = 1
    and fecha_expiracion > now();

  if v_existe > 0 then
    return 1;
  end if;

  return 0;
end//

delimiter ;

/* ============================================================ */
/*  OBJETOS PROGRAMABLES – PROCEDIMIENTOS                       */
/* ============================================================ */

delimiter //

create procedure sp_procesar_peticion(
  in in_ip         varchar(45),
  in in_metodo     varchar(10),
  in in_endpoint   varchar(255),
  in in_user_agent varchar(255),
  in in_score      int,
  in in_id_ataque  int
)
begin
  declare v_id_log       int;
  declare v_criticidad   varchar(20);
  declare v_accion       varchar(20);

  declare exit handler for sqlexception
  begin
    rollback;
  end;

  start transaction;

  if in_score >= 70 then
    set v_accion = 'Bloqueada';
  elseif in_score >= 40 then
    set v_accion = 'Alerta';
  else
    set v_accion = 'Permitida';
  end if;

  insert into peticiones_log (fecha_hora, ip_address, metodo, endpoint, user_agent, score_riesgo, accion_tomada, id_ataque)
  values (now(), in_ip, in_metodo, in_endpoint, in_user_agent, in_score, v_accion, in_id_ataque);

  set v_id_log = last_insert_id();

  if in_score >= 40 then
    set v_criticidad = fn_evaluar_criticidad(in_score);

    insert into alertas (id_log, nivel_criticidad, mensaje, revisada, fecha_generacion)
    values (v_id_log, v_criticidad, concat('Peticion sospechosa desde ', in_ip, ' con score ', in_score), 0, now());
  end if;

  if in_score >= 70 then
    insert into ips_bloqueadas (ip_address, motivo, fecha_bloqueo, fecha_expiracion, activa)
    values (in_ip, concat('Score de riesgo alto: ', in_score), now(), date_add(now(), interval 24 hour), 1)
    on duplicate key update
      motivo           = concat('Score de riesgo alto: ', in_score),
      fecha_bloqueo    = now(),
      fecha_expiracion = date_add(now(), interval 24 hour),
      activa           = 1;
  end if;

  commit;
end//

delimiter ;

delimiter //

create procedure sp_reporte_amenazas(
  in in_fecha_inicio datetime,
  in in_fecha_fin    datetime
)
begin
  select
    ta.nombre         as tipo_ataque,
    count(pl.id_log)  as total_ataques
  from peticiones_log pl
  inner join tipos_ataque ta on pl.id_ataque = ta.id_ataque
  where pl.fecha_hora between in_fecha_inicio and in_fecha_fin
  group by ta.nombre
  order by total_ataques desc;
end//

delimiter ;

/* ============================================================ */
/*  OBJETOS PROGRAMABLES – TRIGGERS                             */
/* ============================================================ */

delimiter //

create trigger trg_auditar_bloqueo_ip
after update on ips_bloqueadas
for each row
begin
  if new.activa = 0 and old.activa = 1 then
    insert into auditoria_sistema (tabla_afectada, accion, detalle_cambio, fecha_hora, usuario_db)
    values ('ips_bloqueadas', 'desbloqueo', concat('IP desbloqueada: ', old.ip_address), now(), current_user());
  end if;
end//

delimiter ;

delimiter //

create trigger trg_validar_alerta
before insert on alertas
for each row
begin
  if new.nivel_criticidad is null or new.nivel_criticidad = '' then
    set new.nivel_criticidad = 'Info';
  end if;
end//

delimiter ;

/* USUARIOS */
/*  SEGURIDAD Y ROLES – CREACION DE USUARIOS                   */
/* ============================================================ */

/* usuario dba_admin: todos los privilegios */
drop user if exists 'dba_admin'@'localhost';
create user 'dba_admin'@'localhost' identified by 'Admin123';
grant all privileges on sentinel_waf.* to 'dba_admin'@'localhost';

/* usuario operador_waf: select, insert, update en tablas operativas */
drop user if exists 'operador_waf'@'localhost';
create user 'operador_waf'@'localhost' identified by 'Operador123';
grant select, insert, update on sentinel_waf.peticiones_log  to 'operador_waf'@'localhost';
grant select, insert, update on sentinel_waf.alertas          to 'operador_waf'@'localhost';
grant select, insert, update on sentinel_waf.ips_bloqueadas   to 'operador_waf'@'localhost';

/* usuario auditor_siem: solo lectura en todas las tablas y execute en sp_reporte_amenazas */
drop user if exists 'auditor_siem'@'localhost';
create user 'auditor_siem'@'localhost' identified by 'Auditor123';
grant execute on procedure sentinel_waf.sp_reporte_amenazas to 'auditor_siem'@'localhost';

/* usuario guardian_bloq: solo gestiona bloqueos, sin acceso a logs o alertas.*/
drop user if exists 'guardian_bloqueos'@'localhost';
create user 'guardian_bloqueos'@'localhost' identified by 'Guard123';

grant select, insert, update on sentinel_waf.ips_bloqueadas to 'guardian_bloqueos'@'localhost';

/* ============================================================ */
/*  DML – DATOS DE PRUEBA                                      */
/* ============================================================ */

insert into tipos_ataque (nombre, descripcion, nivel_riesgo_base) values
  ('SQLi',  'Inyeccion SQL: intento de manipular consultas a la base de datos', 80),
  ('XSS',   'Cross-Site Scripting: inyeccion de scripts maliciosos en el navegador', 60),
  ('LFI',   'Local File Inclusion: intento de acceder a archivos del servidor', 75);

/* ============================================================ */
/*  fin del script sentinel_waf                                 */
/* ============================================================ */

use sentinel_waf;
select * from clientes;





