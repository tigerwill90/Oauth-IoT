-- MySQL Script generated by MySQL Workbench
-- Mon Oct  1 17:38:39 2018
-- Model: New Model    Version: 1.0
-- MySQL Workbench Forward Engineering

SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='TRADITIONAL,ALLOW_INVALID_DATES';

-- -----------------------------------------------------
-- Schema oauth
-- -----------------------------------------------------
DROP SCHEMA IF EXISTS `oauth` ;

-- -----------------------------------------------------
-- Schema oauth
-- -----------------------------------------------------
CREATE SCHEMA IF NOT EXISTS `oauth` DEFAULT CHARACTER SET utf8 ;
USE `oauth` ;

-- -----------------------------------------------------
-- Table `oauth`.`clients`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `oauth`.`clients` ;

CREATE TABLE IF NOT EXISTS `oauth`.`clients` (
  `cli_id` INT NOT NULL AUTO_INCREMENT,
  `cli_client_identification` VARCHAR(80) NOT NULL,
  `cli_client_secret` VARCHAR(255) NOT NULL,
  `cli_client_name` VARCHAR(80) NOT NULL,
  `cli_grant_type` VARCHAR(20) NOT NULL,
  `cli_client_type` VARCHAR(15) NOT NULL,
  `cli_registration_date` DATETIME NOT NULL,
  UNIQUE INDEX `cli_name_UNIQUE` (`cli_client_name` ASC),
  PRIMARY KEY (`cli_id`),
  UNIQUE INDEX `cli_client_id_UNIQUE` (`cli_client_identification` ASC))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `oauth`.`clients_scopes`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `oauth`.`clients_scopes` ;

CREATE TABLE IF NOT EXISTS `oauth`.`clients_scopes` (
  `sco_id` INT NOT NULL AUTO_INCREMENT,
  `sco_service` VARCHAR(30) NOT NULL,
  `sco_cli_id` INT NOT NULL,
  PRIMARY KEY (`sco_id`, `sco_cli_id`),
  INDEX `fk_scopes_clients_idx` (`sco_cli_id` ASC),
  CONSTRAINT `fk_scopes_clients`
    FOREIGN KEY (`sco_cli_id`)
    REFERENCES `oauth`.`clients` (`cli_id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `oauth`.`redirect_uri`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `oauth`.`redirect_uri` ;

CREATE TABLE IF NOT EXISTS `oauth`.`redirect_uri` (
  `red_id` INT NOT NULL AUTO_INCREMENT,
  `red_url` VARCHAR(1000) NOT NULL,
  `red_cli_id` INT NOT NULL,
  PRIMARY KEY (`red_id`, `red_cli_id`),
  INDEX `fk_redirect_uri_clients1_idx` (`red_cli_id` ASC),
  UNIQUE INDEX `red_url_UNIQUE` (`red_url` ASC),
  CONSTRAINT `fk_redirect_uri_clients1`
    FOREIGN KEY (`red_cli_id`)
    REFERENCES `oauth`.`clients` (`cli_id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `oauth`.`resources`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `oauth`.`resources` ;

CREATE TABLE IF NOT EXISTS `oauth`.`resources` (
  `res_id` INT NOT NULL AUTO_INCREMENT,
  `res_identification` VARCHAR(80) NOT NULL,
  `res_secret` VARCHAR(255) NOT NULL,
  `res_audience` VARCHAR(80) NOT NULL,
  `res_registration_date` DATETIME NULL,
  `res_pop_method` VARCHAR(30) NOT NULL,
  `res_key_size` INT NOT NULL,
  `res_algorithm_encryption` VARCHAR(25) NOT NULL,
  `res_tls` TINYINT NOT NULL,
  `res_transmission_algorithm` VARCHAR(25) NULL,
  PRIMARY KEY (`res_id`),
  UNIQUE INDEX `res_identification_UNIQUE` (`res_identification` ASC),
  UNIQUE INDEX `res_audience_UNIQUE` (`res_audience` ASC))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `oauth`.`users`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `oauth`.`users` ;

CREATE TABLE IF NOT EXISTS `oauth`.`users` (
  `use_id` INT NOT NULL AUTO_INCREMENT,
  `use_username` VARCHAR(80) NOT NULL,
  `use_email` VARCHAR(80) NOT NULL,
  `use_password` VARCHAR(80) NOT NULL,
  `use_refresh_token` TINYINT NOT NULL,
  PRIMARY KEY (`use_id`),
  UNIQUE INDEX `use_username_UNIQUE` (`use_username` ASC),
  UNIQUE INDEX `use_email_UNIQUE` (`use_email` ASC))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `oauth`.`resources_scopes`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `oauth`.`resources_scopes` ;

CREATE TABLE IF NOT EXISTS `oauth`.`resources_scopes` (
  `res_sco_id` INT NOT NULL AUTO_INCREMENT,
  `res_sco_service` VARCHAR(30) NOT NULL,
  `res_sco_description` VARCHAR(1000) NOT NULL,
  `res_sco_uri` VARCHAR(1000) NOT NULL,
  `res_sco_name` VARCHAR(80) NOT NULL,
  `res_sco_method` VARCHAR(10) NOT NULL,
  `res_sco_res_id` INT NOT NULL,
  PRIMARY KEY (`res_sco_id`, `res_sco_res_id`),
  INDEX `fk_resources_scopes_resources1_idx` (`res_sco_res_id` ASC),
  CONSTRAINT `fk_resources_scopes_resources1`
    FOREIGN KEY (`res_sco_res_id`)
    REFERENCES `oauth`.`resources` (`res_id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;

-- -----------------------------------------------------
-- Data for table `oauth`.`resources`
-- -----------------------------------------------------
START TRANSACTION;
USE `oauth`;
INSERT INTO `oauth`.`resources` (`res_id`, `res_identification`, `res_secret`, `res_audience`, `res_registration_date`, `res_pop_method`, `res_key_size`, `res_algorithm_encryption`, `res_tls`, `res_transmission_algorithm`) VALUES (1, '012345', '0123456789012345', 'iot_1', NULL, 'introspection', 16, 'AES128ECB', 0, 'AES128ECB');
INSERT INTO `oauth`.`resources` (`res_id`, `res_identification`, `res_secret`, `res_audience`, `res_registration_date`, `res_pop_method`, `res_key_size`, `res_algorithm_encryption`, `res_tls`, `res_transmission_algorithm`) VALUES (2, '543210', '5432109876543210', 'iot_2', NULL, 'introspection', 32, 'AES256CBC', 1, 'none');
INSERT INTO `oauth`.`resources` (`res_id`, `res_identification`, `res_secret`, `res_audience`, `res_registration_date`, `res_pop_method`, `res_key_size`, `res_algorithm_encryption`, `res_tls`, `res_transmission_algorithm`) VALUES (3, '051423', '0123459876543210', 'iot_3', NULL, 'introspection', 32, 'none', 1, 'none');

COMMIT;


-- -----------------------------------------------------
-- Data for table `oauth`.`users`
-- -----------------------------------------------------
START TRANSACTION;
USE `oauth`;
INSERT INTO `oauth`.`users` (`use_id`, `use_username`, `use_email`, `use_password`, `use_refresh_token`) VALUES (1, 'tigerwill90', 'c@c.com', '$2y$10$REEXSPDySgaeHg.NbWboaOeERb4ifxfXbm1IJYw.qbVdpmxsWUCOa', 1);

COMMIT;


-- -----------------------------------------------------
-- Data for table `oauth`.`resources_scopes`
-- -----------------------------------------------------
START TRANSACTION;
USE `oauth`;
INSERT INTO `oauth`.`resources_scopes` (`res_sco_id`, `res_sco_service`, `res_sco_description`, `res_sco_uri`, `res_sco_name`, `res_sco_method`, `res_sco_res_id`) VALUES (1, 'Rgyro', 'Calculate the direction of wind', 'http://192.168.192.80/wind/direction', 'NodeMCU : Wind direction', 'GET', 2);
INSERT INTO `oauth`.`resources_scopes` (`res_sco_id`, `res_sco_service`, `res_sco_description`, `res_sco_uri`, `res_sco_name`, `res_sco_method`, `res_sco_res_id`) VALUES (2, 'Raneno', 'Calculate the speed of wind', 'http://192.168.192.0/wind/speed', 'NodeMCU : Wind speed', 'GET', 2);
INSERT INTO `oauth`.`resources_scopes` (`res_sco_id`, `res_sco_service`, `res_sco_description`, `res_sco_uri`, `res_sco_name`, `res_sco_method`, `res_sco_res_id`) VALUES (3, 'Rmove', 'Detect any movement in front of sensor', 'https://192.168.192.0/detect', 'Raspberry Pi : Movement detection', 'GET', 3);

COMMIT;

