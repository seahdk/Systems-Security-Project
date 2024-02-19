SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+08:00";

--
-- Database: `pythonlogin`
--
CREATE DATABASE IF NOT EXISTS `pythonlogin` DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci;
USE `pythonlogin`;

-- --------------------------------------------------------

--
-- Table structure for table `accounts`
--

CREATE TABLE `accounts` (
  `id` int(11) NOT NULL,
  `username` varchar(50) NOT NULL,
  `password` varchar(80) NOT NULL,
  `email` varchar(200) NOT NULL,
  `role` varchar(30) NOT NULL DEFAULT 'user',
  `country` varchar(100) NOT NULL,
  `is_blocked` varchar(100) NOT NULL,
  `phone` varchar(12) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `logs`
--

CREATE TABLE `logs` (
  `activity_time` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `user_id` varchar(10) NOT NULL DEFAULT '0',
  `ip_address` varchar(30) NOT NULL,
  `city` varchar(100) DEFAULT NULL,
  `region` varchar(100) DEFAULT NULL,
  `country_name` varchar(100) DEFAULT NULL,
  `continent_code` varchar(100) DEFAULT NULL,
  `latitude` varchar(100) DEFAULT NULL,
  `longitude` varchar(100) DEFAULT NULL,
  `network_provider` varchar(200) DEFAULT NULL,
  `is_active_session` varchar(100) NOT NULL DEFAULT 'Inactive'
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `notifications`
--

CREATE TABLE `notifications` (
  `id` int(11) NOT NULL,
  `time` datetime DEFAULT current_timestamp(),
  `reason` varchar(200) NOT NULL,
  `malicious_input` varchar(10000) DEFAULT NULL,
  `country` varchar(200) DEFAULT NULL,
  `coordinates` varchar(100) DEFAULT NULL,
  `ip_address` varchar(100) DEFAULT NULL,
  `is_active_session` varchar(100) DEFAULT NULL,
  `ip_blocked` varchar(100) DEFAULT NULL,
  `username` varchar(100) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--

ALTER TABLE `accounts`
  ADD PRIMARY KEY (`id`);


ALTER TABLE `logs`
  ADD PRIMARY KEY (`user_id`,`ip_address`);


ALTER TABLE `notifications`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT for table `accounts`
--
ALTER TABLE `accounts`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `notifications`
--
ALTER TABLE `notifications`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;
COMMIT;
