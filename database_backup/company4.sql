-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Vært: mysql
-- Genereringstid: 25. 11 2024 kl. 17:06:25
-- Serverversion: 9.0.1
-- PHP-version: 8.2.8

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `company`
--

-- --------------------------------------------------------

--
-- Struktur-dump for tabellen `items`
--

CREATE TABLE `items` (
  `item_pk` char(36) NOT NULL,
  `item_user_fk` char(36) DEFAULT NULL,
  `item_title` varchar(50) NOT NULL,
  `item_price` decimal(5,2) NOT NULL,
  `item_image_1` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  `item_image_2` varchar(50) NOT NULL,
  `item_image_3` varchar(50) NOT NULL,
  `item_created_at` int UNSIGNED DEFAULT NULL,
  `item_deleted_at` int UNSIGNED DEFAULT NULL,
  `item_blocked_at` int UNSIGNED DEFAULT NULL,
  `item_updated_at` int UNSIGNED DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Data dump for tabellen `items`
--

INSERT INTO `items` (`item_pk`, `item_user_fk`, `item_title`, `item_price`, `item_image_1`, `item_image_2`, `item_image_3`, `item_created_at`, `item_deleted_at`, `item_blocked_at`, `item_updated_at`) VALUES
('902b81dd-007a-42e3-9e1a-ea65f25b69dd', '0d2c931d-39b3-42db-af5d-d048a541c9ff', 'Julekager', 20.00, '9879f7aa-23c0-4113-92e1-ba9319c81454.JPG', '9879f7aa-23c0-4113-92e1-ba9319c81454.JPG', '60b5cfa2-581c-4440-b0e4-db75fb1ebaba.JPG', 1732478844, 0, 0, 1732483748),
('9662887c-d824-428d-a66a-bf722aa8ee7b', '0d2c931d-39b3-42db-af5d-d048a541c9ff', 'Korn', 20.00, '5c4e2115-ce3d-4237-ae81-2d75cf66ef74.png', 'a3dae23c-1569-474a-b3a8-aa5466cd85dc.png', 'c40e26fa-3be0-4aaa-856a-7ca9784ac876.png', 1732478789, 0, 0, 0),
('ee984a49-cfe1-4ff7-8969-cbb1f3fce919', '0d2c931d-39b3-42db-af5d-d048a541c9ff', 'Æbler', 43.00, 'b024aa5f-131c-4525-b5f2-8f68141c3a4d.png', 'cab2e3e1-01a2-42cb-a22b-95f491ff361e.png', '4f99efb8-f689-4a78-93de-dad9f14cc28a.png', 1732478768, 0, 0, 0);

-- --------------------------------------------------------

--
-- Struktur-dump for tabellen `roles`
--

CREATE TABLE `roles` (
  `role_pk` char(36) NOT NULL,
  `role_name` varchar(10) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Data dump for tabellen `roles`
--

INSERT INTO `roles` (`role_pk`, `role_name`) VALUES
('16fd2706-8baf-433b-82eb-8c7fada847da', 'admin'),
('c56a4180-65aa-42ec-a945-5fd21dec0538', 'customer'),
('f47ac10b-58cc-4372-a567-0e02b2c3d479', 'partner'),
('9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15', 'restaurant');

-- --------------------------------------------------------

--
-- Struktur-dump for tabellen `users`
--

CREATE TABLE `users` (
  `user_pk` char(36) NOT NULL,
  `user_name` varchar(20) NOT NULL,
  `user_last_name` varchar(20) NOT NULL,
  `user_email` varchar(100) NOT NULL,
  `user_password` varchar(255) NOT NULL,
  `user_avatar` varchar(50) DEFAULT NULL,
  `user_created_at` int UNSIGNED DEFAULT NULL,
  `user_deleted_at` int UNSIGNED DEFAULT NULL,
  `user_blocked_at` int UNSIGNED DEFAULT NULL,
  `user_updated_at` int UNSIGNED DEFAULT NULL,
  `user_verified_at` int UNSIGNED DEFAULT NULL,
  `user_verification_key` char(36) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Data dump for tabellen `users`
--

INSERT INTO `users` (`user_pk`, `user_name`, `user_last_name`, `user_email`, `user_password`, `user_avatar`, `user_created_at`, `user_deleted_at`, `user_blocked_at`, `user_updated_at`, `user_verified_at`, `user_verification_key`) VALUES
('000d6183-bfe1-49e6-af87-d386990dcf14', 'Alexandra', '', 'cclark@example.net', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_5.jpg', 1732450886, 0, 0, 0, 1732450886, '73e87ac8-d1b2-4d7c-903f-3095d50eb352'),
('01cb4104-b442-4460-bad7-a9694d366858', 'Samantha', '', 'nobledeborah@example.org', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_34.jpg', 1732450883, 0, 0, 0, 0, '7218988a-ef5b-46b4-a13f-559672fed102'),
('02bb1089-ed87-44c9-8b5f-3cb252e5e22a', 'Mark', '', 'cruzcheryl@example.com', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_84.jpg', 1732450881, 0, 0, 0, 0, '10229dfc-aa23-48f1-9eea-e53078b55baa'),
('034f515f-c83a-4c53-946c-1e1f2a4684aa', 'Larry', 'Smith', 'garrettjason@hotmail.com', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_91.jpg', 1732450879, 0, 0, 0, 1732450879, 'bb2ff1bc-a7be-40a3-983a-5b5b59c7c235'),
('06f4712c-8054-4b52-9342-615099fb67f2', 'Julie', 'Eriksen', 'j@hotmail.com', 'scrypt:32768:8:1$t158ZlYBBzwGuR32$a7c12a23e86ca30e8d48ed6a9ece85e187488ef7155477d289931df3d530f33d0250736d7b5aab47bd0aa39c94f78de8333e53dc765af689c01249da3e2a7495', '', 1732484640, 0, 0, 0, 1732484671, 'b847e765-a6d9-40b1-8a6c-74380366bab8'),
('072b131d-9ed0-49fc-9426-7511b5eddc12', 'Natasha', '', 'gberger@example.net', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_60.jpg', 1732450880, 0, 0, 0, 1732450880, '0502b281-9bc4-40fd-b1b3-a09385fd4b09'),
('087df979-bcff-4ef1-9c30-f968957a16e8', 'Michael', 'Griffith', 'rita70@gmail.com', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_26.jpg', 1732450879, 0, 0, 0, 1732450879, '064da1c2-530e-4b45-9b73-5a2ca61c3ecc'),
('09ee98e0-0535-475c-83e9-12c570339faf', 'Joseph', 'Lewis', 'gshaffer@example.org', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_81.jpg', 1732450880, 0, 0, 0, 0, '063ea5c6-841a-456f-83b5-be3564d4a319'),
('0ac52fca-bdc9-4fb4-8588-e92c59d57fef', 'Heather', 'Taylor', 'eric84@example.net', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_100.jpg', 1732450880, 0, 0, 0, 0, '4ce1f471-fb62-4488-bc51-ab78d3d54ebf'),
('0cd80f30-f2cb-4f61-aa0c-8ec09be06789', 'Tiffany', 'Jimenez', 'jryan@website.co', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_48.jpg', 1732450879, 0, 0, 0, 0, 'af453786-af40-4840-98db-b54cfd595d3c'),
('0d2c931d-39b3-42db-af5d-d048a541c9ff', 'Terri', '', 'restaurant@hotmail.com', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_91.jpg', 1732450883, 0, 0, 0, 1, 'c305b88b-de44-4c0e-9fc8-f995a58d41bb'),
('0f9c002a-5bb4-4003-8309-eb72f0c06a0b', 'Michael', 'Harvey', 'daviscody@website.co', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_10.jpg', 1732450879, 0, 0, 0, 1732450879, 'fe478bd9-5482-4f2e-8d6a-882d5d580267'),
('0ff320d4-a617-45f0-a241-52987fa0a421', 'Philip', '', 'fklein@example.org', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_41.jpg', 1732450884, 0, 0, 0, 0, '6a04df12-80aa-4397-91c7-0f5cbb52acda'),
('10d07662-611a-4d75-9c64-9fc6dc767439', 'Jesse', 'Lang', 'morenokimberly@example.com', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_30.jpg', 1732450880, 0, 0, 0, 0, 'de703723-7157-489f-a5b8-69309879795b'),
('123d5c47-e948-4ce5-b299-acc4133bf1cc', 'Kimberly', '', 'ashley33@example.com', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_33.jpg', 1732450881, 0, 0, 0, 1732450881, '78ad367e-0223-402f-af61-19bcaaa613f8'),
('133d2d8a-5c1d-4c5e-b693-dc26453b84d9', 'Ian', 'Price', 'beasleyfelicia@example.org', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_36.jpg', 1732450880, 0, 0, 0, 0, 'a1e77073-f08c-4cd2-abe1-e26db2ffc58a'),
('145b6d1a-eeef-40e2-a43f-f1bdb2faecb5', 'John', '', 'michael84@example.com', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_84.jpg', 1732450887, 0, 0, 0, 0, '961c69d3-fc53-47e2-9e21-53997c0ba801'),
('19bf720e-9319-4455-beb1-79968fbfac09', 'Samuel', '', 'everettstephanie@example.org', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_3.jpg', 1732450887, 0, 0, 0, 0, '79729248-93a9-4377-8ce4-bca5a8701ec8'),
('1b56c196-9cf1-43c7-a658-eafd6711850e', 'Kyle', '', 'ashley81@example.org', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_38.jpg', 1732450882, 0, 0, 0, 0, '13c17827-4411-40d2-8128-737374c93ac8'),
('1efb3331-6370-4cd6-942d-296d6cf303b2', 'Oli', 'jenbo', 'jen@hotmail.com', 'scrypt:32768:8:1$kvrei5MLJTBdMwZK$ed16bea4d30996eab635b583fcfc8e798b0de2017ff84069c3ed2eb2f275f24b773aaa946dedd90005edc12d3bcd39bfdc27a98c2a77d9b3ffbe6bbcadc55860', '', 1732554040, 0, 0, 0, 0, '25726892-32b8-469f-8df2-27d9352e585e'),
('1fe1243e-3dc3-45ad-bb91-f7e7dabafea4', 'John', 'Hernandez', 'castillojoseph@example.com', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_94.jpg', 1732450879, 0, 0, 0, 0, '5e299f81-2d0e-4b28-b6b6-05b8bb63132e'),
('20a40f63-de41-430c-8693-90efb4e958dc', 'Jennifer', '', 'gwells@example.net', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_17.jpg', 1732450881, 0, 0, 0, 1732450881, 'd2b6094a-ba38-4106-a514-fe4c29e1ef48'),
('21631177-8334-43be-8529-cdf579273af0', 'Kevin', 'Duran', 'connieknight@example.com', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_63.jpg', 1732450880, 0, 0, 0, 1732450880, '350c369c-d5b2-4aea-a2a6-3cb5cc08f240'),
('2480f42c-a0a7-497c-b68b-86a06d8fb320', 'Alexander', 'Chase', 'jonesjennifer@hotmail.com', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_14.jpg', 1732450879, 0, 0, 0, 0, '2c987b77-e826-4d18-b40e-9b9ccd06d108'),
('263d6b2a-78b1-4425-9d80-05f954c736f4', 'Amanda', 'Coleman', 'mike56@website.co', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_24.jpg', 1732450879, 0, 0, 0, 0, 'fb7f0b08-ccdf-4048-803d-12619aaaa7e1'),
('2672b12c-01a5-43a8-8f78-d6eb571489bb', 'Amy', '', 'shelbycastaneda@example.com', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_63.jpg', 1732450884, 0, 0, 0, 1732450884, '8ff95428-4987-4b8c-a938-fd842788e379'),
('26f98772-7157-4dd4-9e4e-3480787c6e44', 'Molly', 'Martinez', 'toddjohnson@example.com', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_89.jpg', 1732450879, 0, 0, 0, 0, '089edeb7-748d-4645-a5cb-07fc355c8ed7'),
('27765da5-bc36-49bb-8f20-ca42bd9d79c2', 'Dawn', '', 'penny18@example.org', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_10.jpg', 1732450884, 0, 0, 0, 0, '6ba1ed41-65b6-47c9-8020-a77f094d48e6'),
('2bee73fa-3462-42ac-8f75-dc38b8e0757e', 'Chad', 'Moore', 'tammy00@example.org', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_87.jpg', 1732450880, 0, 0, 0, 0, '124c3bc9-29f2-4d23-aae7-f2213cc53921'),
('2db20c77-236e-459a-9ab3-2f710f4b9ef6', 'Jose', 'Dean', 'smithsteven@example.net', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_43.jpg', 1732450880, 0, 0, 0, 0, '1dc0f2c9-75a1-4000-9ca3-0b5c6bf3a820'),
('2fe7d474-3438-4456-9959-da9e1037c2c4', 'Denise', 'Rosales', 'howardhendrix@website.co', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_10.jpg', 1732450879, 0, 0, 0, 1732450879, '8912fac4-595e-4a90-a4c5-ebde429ecdd8'),
('30d7b56b-078b-438d-800c-b5bea795620a', 'Michael', 'Hall', 'tylerangela@gmail.com', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_39.jpg', 1732450879, 0, 0, 0, 0, '49a6052d-34c1-47eb-a2ef-2e03a6b1e23e'),
('31b83b10-45d7-4b57-acd2-825684e778b6', 'John', 'Johnson', 'nicholas47@example.com', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_94.jpg', 1732450880, 0, 0, 0, 1732450880, '31e12a27-fec2-4573-8d37-56d9f467de8a'),
('31d35390-e06b-4c17-bf1a-f2a845e2c14f', 'Timothy', 'Shepard', 'kjenkins@mydomain.net', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_8.jpg', 1732450879, 0, 0, 0, 0, 'cd71b163-04f3-4bc8-983e-1f46c52f2e1e'),
('3b2615ee-fbb6-4446-a5a2-fe23b0191ae1', 'Justin', 'Perry', 'uvargas@example.com', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_4.jpg', 1732450879, 0, 0, 0, 0, '5d5a1a10-1a51-4e9d-b125-b6f35be6376c'),
('3bcfd481-160e-45fb-ac2c-abd010342562', 'Carla', '', 'denniscollier@example.org', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_78.jpg', 1732450885, 0, 0, 0, 1732450885, 'c55dea8a-1cc4-442d-96e8-7caf45cc8250'),
('3c562f8f-6802-46eb-a306-e252924c048a', 'Vincent', '', 'denisehayden@example.net', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_22.jpg', 1732450887, 0, 0, 0, 0, 'aa0df03e-64ec-4437-8322-2dc25215957d'),
('3e4ff5d1-fbf0-4259-beac-b6ba725fc0db', 'Joshua', '', 'jacob32@example.net', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_76.jpg', 1732450882, 0, 0, 0, 0, '6c2f6cb5-213a-4331-8927-d208da788123'),
('3fd0a1f9-d596-4850-88de-b6e490b73bd8', 'John', 'Jones', 'lisaayala@example.org', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_97.jpg', 1732450880, 0, 0, 0, 0, '01c3f7fc-1676-4fe7-bd61-1d4186efbd9f'),
('4218788d-03b7-4812-bd7d-31c8859e92d8', 'John', 'Customer', 'customer@fulldemo.com', 'scrypt:32768:8:1$z9PI0Th73YxAvdqv$1696bf2c5f327efd1a0a35bd9a1099db5a76fe0bf24a14f2906c89d6f75ae17a0ba77a3fae3ff2b03dc98cc2970f7a867fc137691b4b9ccf3af0eac4671347bd', 'profile_11.jpg', 1732450879, 0, 0, 0, 1732450879, '783d34b6-e358-4290-8a39-9939471a255d'),
('42630eb6-8c52-4bf0-99f4-3c6bfb535a6b', 'Robert', '', 'joselong@example.org', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_63.jpg', 1732450883, 0, 0, 0, 0, '4f6c8f0f-6075-41be-a892-fbfa0330d3cf'),
('42ea150f-fb86-4602-8ecb-c47340ac031b', 'Amanda', 'Travis', 'sedwards@example.com', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_11.jpg', 1732450879, 0, 0, 0, 1732450879, 'deb34373-c20b-406a-bf11-9c9ac7dff197'),
('445204b1-984f-4cf4-9eb5-00b07ea2b5b6', 'Diana', 'Walsh', 'youngcynthia@example.net', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_62.jpg', 1732450880, 0, 0, 0, 0, '61fecc6e-46eb-48bf-a2e3-c04f2bc877ca'),
('453772c3-a9ba-4c11-bcda-0287d8324dde', 'Stephen', 'Richards', 'mkennedy@example.org', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_52.jpg', 1732450880, 0, 0, 0, 0, 'b20ab09e-e565-4eb9-97fa-7e68fedd4ef6'),
('480f1c22-47e0-4072-ac13-2d13a64234b9', 'Paul', 'Freeman', 'jeremyherrera@example.org', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_47.jpg', 1732450880, 0, 0, 0, 1732450880, '5ffcd135-1263-465b-aeea-93302b736e54'),
('48c6351a-9e77-486d-a70a-908e7ea7891e', 'Rebecca', 'Riggs', 'toddhughes@example.com', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_3.jpg', 1732450880, 0, 0, 0, 0, 'a0d93302-0b1e-4bd9-9f7e-78044dd928f6'),
('492ce812-b3bd-4aea-a919-612c483478c5', 'Darryl', 'Walker', 'fosterjoseph@example.com', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_22.jpg', 1732450879, 0, 0, 0, 0, '173ab0e4-8977-4c61-adc5-2051eab84e4b'),
('4aebd108-8ef2-42e6-a202-b15143f721c5', 'Sean', '', 'jessicamcclure@example.org', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_64.jpg', 1732450885, 0, 0, 0, 1732450885, 'a6740156-8680-40fa-8885-8eb50a4746f9'),
('53194d76-d657-4238-9580-1e1294eda815', 'Richard', 'Bell', 'wburns@example.com', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_52.jpg', 1732450880, 0, 0, 0, 1732450880, '550828f6-b9d3-4bc0-a037-fc87f505b33d'),
('53fc94f7-6c2d-4b04-a27f-7bd915fd30aa', 'Eric', '', 'jefffoley@example.org', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_87.jpg', 1732450883, 0, 0, 0, 1732450883, '4d2f8039-42b7-4408-b0fd-d70275bcca72'),
('540a6c6d-ef81-490c-837b-02de30eb2d9f', 'John', 'Partner', 'partner@fulldemo.com', 'scrypt:32768:8:1$wcsLhAvixQxhwXg4$f3993cd783f0783bd0a8134af5c4dbe6ac7382b0bfdfa2acd36874781d93ca4d3e10c2b7023604587177f0bc543d3c53c3db41aef964e6b1fe9963978c395662', 'profile_12.jpg', 1732450879, 0, 0, 0, 1732450879, '512b56c2-0c22-4a80-831d-94d331e8cfc4'),
('553a0df0-b9db-435b-a65a-55bc572020df', 'Rachel', '', 'jillschultz@example.net', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_69.jpg', 1732450886, 0, 0, 0, 1732450886, 'f1e6052d-24b3-49df-a398-f3bbe183eac7'),
('5591d016-399e-4784-8c63-150e9e1694c4', 'Katie', '', 'gonzalestammy@example.com', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_26.jpg', 1732450883, 0, 0, 0, 1732450883, '5094689c-5e76-46cb-948c-bb8f2e32079e'),
('585d1a54-b184-4a70-acf2-d6dfaf182100', 'Elizabeth', 'Whitaker', 'nguyenjerry@example.com', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_19.jpg', 1732450880, 0, 0, 0, 1732450880, 'd1f7305a-9d41-43e3-8f8e-089fa4c8c8fa'),
('5ac06980-7eaa-423e-9503-fb63a50d232d', 'John', 'Lloyd', 'lisa28@example.com', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_22.jpg', 1732450879, 0, 0, 0, 0, '9efa9c47-d3eb-446e-810f-dc5822be807b'),
('5e70ce28-3ec7-476a-94a4-772796e29c4a', 'Brittney', 'Smith', 'christopher91@example.net', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_33.jpg', 1732450880, 0, 0, 0, 1732450880, '85009567-9d74-4e3f-8ed6-352de92d026c'),
('5ea6e922-bd5d-43be-9592-eb468bb15e2e', 'Nicole', 'Wolf', 'marissaallen@example.com', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_64.jpg', 1732450879, 0, 0, 0, 1732450879, 'e8a3aa1c-4292-4901-b97f-a10335052290'),
('5ea8d9eb-a906-44fd-86db-7e2a414f9f1e', 'Douglas', '', 'tbaker@example.com', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_84.jpg', 1732450886, 0, 0, 0, 0, '97482f0c-c807-4c48-9e55-7977d5aaafce'),
('5f0a69f1-63cd-4590-b006-ee653c960889', 'Jul', 'jul', 'jul@hotmail.com', 'scrypt:32768:8:1$l6mQChpKXrNI6sE0$80de210730eea7f2894348e718fcbff5637a108d653240a79b65611a0ef183fe091be0135c97f5959dbba52d685f9673a3deb928286e222685ad333751c639de', '', 1732554247, 0, 0, 0, 0, 'dd5d1e9e-af5e-4701-acba-6f81af150297'),
('5fcb29ef-fe4d-429e-8da1-a1f24baf27a8', 'Christian', 'Garcia', 'flambert@example.net', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_33.jpg', 1732450880, 0, 0, 0, 1732450880, '44b18931-5c6f-4d32-8b3e-969081177377'),
('61a34414-1156-4a61-9ba3-121bc0095978', 'Darren', 'Frederick', 'weberedward@example.org', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_44.jpg', 1732450880, 0, 0, 0, 0, 'a5b82211-653b-4cbc-b14a-e24d86c996ca'),
('627b3117-a63c-4a8c-a294-949fbf5e5833', 'Victoria', 'Johnson', 'krandall@mydomain.net', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_28.jpg', 1732450879, 0, 0, 0, 0, 'f30b11c8-5963-4a41-85be-46ce7ec8e955'),
('640e2ffb-c15d-402c-9701-7b8d1751a13a', 'Michele', 'Stokes', 'margaretserrano@example.net', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_21.jpg', 1732450880, 0, 0, 0, 0, '184e547c-09ed-4f9a-a5a6-04588aac0a03'),
('6ae116a3-46b7-47b1-b4eb-4732acaf28e4', 'Michael', '', 'mary21@example.com', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_72.jpg', 1732450884, 0, 0, 0, 1732450884, 'c591d55e-1902-4e83-9942-8c84b420cf85'),
('6b7df1fa-0e28-489a-80e3-e020112a5779', 'Troy', 'Kidd', 'jenniferhenderson@fakemail.io', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_53.jpg', 1732450879, 0, 0, 0, 1732450879, 'a00b6b32-38bd-43e9-a846-cc47800121e9'),
('6c14f210-d22f-4b39-b842-7bf683965f5d', 'Katherine', 'Romero', 'xcabrera@gmail.com', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_15.jpg', 1732450879, 0, 0, 0, 1732450879, '662969a8-3e7e-4c7b-8806-e37a2964be02'),
('6f1049ea-0957-4fef-ae67-0392099f437e', 'Tommy', 'Johnson', 'dfisher@example.net', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_12.jpg', 1732450880, 0, 0, 0, 1732450880, 'a1d0f28a-b588-4d93-b335-ad112ea70dd5'),
('6f5d5fcd-d791-40a3-9be6-8999d2319a57', 'Matthew', 'Morris', 'katie08@hotmail.com', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_75.jpg', 1732450879, 0, 0, 0, 0, '668d4543-181b-4aa9-9ca8-89825829c733'),
('6ff79666-4e24-4774-8189-10447043af54', 'Santiago', 'Donoso', 'admin@fulldemo.com', 'scrypt:32768:8:1$0FPFAjElPiokgmXQ$aba154c46ced244728c1cd8e136964d8dbbca363e22b2b6a8a1d29a25fd0059eb4dc211b20077dd99c3052739491ca9ed0dffaa80576928ff3858109561fa9ed', 'profile_10.jpg', 1732450879, 0, 0, 1732484422, 1732450879, 'e1d4cb6c-d30c-44ce-8f03-4131a417c591'),
('706fa6cd-54ae-4792-9167-47fdbe5613a9', 'Jocelyn', '', 'vancematthew@example.com', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_71.jpg', 1732450885, 0, 0, 0, 0, '9fd2a112-f87a-4ca3-a277-4a504147571f'),
('71ff21f8-118a-489e-9e70-fca71927dede', 'Jennifer', '', 'joshua66@example.org', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_69.jpg', 1732450885, 0, 0, 0, 1732450885, '2f20c967-7e34-4a18-b419-ef4eca5798c6'),
('72ec3f92-2b59-48c3-bd25-acfd24a6c7c6', 'Thomas', 'Novak', 'perezamanda@example.net', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_21.jpg', 1732450880, 0, 0, 0, 1732450880, '4ea1ec74-f286-4ceb-9fb9-1a61a4b5fafb'),
('732749ca-ca6e-4ef6-8204-53f37724745d', 'Johnny', 'Rose', 'davidperry@fakemail.io', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_35.jpg', 1732450879, 0, 0, 0, 0, '7e972f93-922e-45cf-80b0-09ecf644f276'),
('7947a80d-a4ae-418e-8f6e-52be069e4fb1', 'Joel', '', 'jesusjones@example.org', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_63.jpg', 1732450881, 0, 0, 0, 0, 'aa7be663-48e1-4efa-9fb2-1951af126a59'),
('7acd8943-1667-4982-9b1b-fa974cac232b', 'Julia', 'Barr', 'juan77@gmail.com', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_55.jpg', 1732450879, 0, 0, 0, 0, '23afbf65-1178-475b-a62c-444b81b368e1'),
('7b30040e-cd2b-491b-b77e-ef971f44c495', 'Seth', 'Mendoza', 'webbjack@gmail.com', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_6.jpg', 1732450879, 0, 0, 0, 0, 'c7d081c5-2a41-434f-8490-f4effca4848e'),
('7d151992-e908-4bfc-acdb-76e2e86c06e6', 'Debra', 'Powers', 'armstrongmichael@gmail.com', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_87.jpg', 1732450879, 0, 0, 0, 0, '3456e8c6-4c22-4380-9e49-5ce56497d5bf'),
('7f73d660-346e-4b50-8759-8e4fea2370a9', 'Daniel', 'Wilcox', 'smithphillip@testsite.org', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_79.jpg', 1732450879, 0, 0, 0, 1732450879, 'ff529165-37e0-40e5-a2a2-ec3bc7cb50a7'),
('805148b4-f629-4647-8ddd-0d8a338715ea', 'Gabriel', 'Thompson', 'brianawilson@testsite.org', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_84.jpg', 1732450879, 0, 0, 0, 0, '81ffe93b-4349-43d4-8eac-f14076fb0f05'),
('82b94871-7988-456f-ad7c-f0dbff18fae2', 'James', 'Padilla', 'ftanner@example.com', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_65.jpg', 1732450880, 0, 0, 0, 1732450880, 'f79973c2-3cb4-47b9-a613-9ab8658e847e'),
('843628c8-7e27-4e21-bfed-421228dd6f22', 'Scott', 'Baker', 'hhensley@example.com', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_66.jpg', 1732450880, 0, 0, 0, 0, '4c5c63bd-e36f-4211-a93e-2a59351803e5'),
('8466b24c-eef5-48c9-926e-939d4e9aff0b', 'Troy', 'Russo', 'leahreed@mydomain.net', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_5.jpg', 1732450879, 0, 0, 0, 1732450879, 'b940c0b7-d366-489e-a94f-5fc122316d69'),
('8500227e-cd04-4329-9c2c-2f89cb72c37a', 'Bonnie', '', 'smithjohnny@example.com', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_8.jpg', 1732450882, 0, 0, 0, 1732450882, '44deb12e-de23-4296-bb87-ae4aab29ce43'),
('855d6b52-7f4d-4513-a07a-f7c959831efa', 'Cassandra', '', 'caleb62@example.com', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_18.jpg', 1732450886, 0, 0, 0, 0, '3d677cb5-e9dd-4d9e-acb4-bf2d79ecf42b'),
('86333921-c90c-4e80-880b-1a6a346f8f32', 'Anne', '', 'xsantana@example.com', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_98.jpg', 1732450885, 0, 0, 0, 1732450885, 'f299a038-6eb6-420d-bfba-f2481631ec50'),
('86e6f3bc-e51f-4bfa-9877-d089e5741607', 'Daniel', '', 'larrychandler@example.net', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_8.jpg', 1732450883, 0, 0, 0, 1732450883, 'e0750fcc-89be-408b-87a1-7b95831bbec5'),
('896a78f7-c481-4503-8a2b-6b13a779a589', 'Sarah', 'Jones', 'patelalex@fakemail.io', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_57.jpg', 1732450879, 0, 0, 0, 0, '5a10bfdc-ea41-41f9-871a-c7ba0c6aba00'),
('8a5870c7-11e2-4f61-9089-7845d41cd633', 'Melissa', '', 'evalentine@example.org', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_1.jpg', 1732450886, 0, 0, 0, 0, 'a679b697-84d2-4c29-ab56-7b513f0a630c'),
('8b867f65-4dc4-481c-ae90-e5da1fedd3ac', 'Jeremy', 'Jacobson', 'brandon51@testsite.org', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_93.jpg', 1732450879, 0, 0, 0, 0, 'cdcda5e7-fea7-4f53-b06b-b511ceab9183'),
('8d4a27c5-a8da-441e-b296-433076ea94e7', 'Ashley', '', 'lorirodriguez@example.net', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_97.jpg', 1732450887, 0, 0, 0, 0, 'eb2aea30-5196-414a-aa03-8221384aa221'),
('8d8fadbb-5824-474b-aba8-c680aa3c3a41', 'Carrie', 'Larson', 'qli@example.net', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_1.jpg', 1732450880, 0, 0, 0, 1732450880, '38e154c4-1c20-4a8b-8102-81b99e8dc0c2'),
('8ec09a4f-368a-4841-a1dc-905d4fd72cbc', 'Hannah', '', 'fshepherd@example.com', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_79.jpg', 1732450881, 0, 0, 0, 1732450881, '58695eb5-bd93-44b2-a2ad-a690ef84361f'),
('8f43ca25-9758-4b4a-80f2-e1e982fed054', 'Micheal', 'Taylor', 'rbarker@example.net', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_13.jpg', 1732450880, 0, 0, 0, 1732450880, 'af3e3b7b-485d-43c7-8607-ae8fd561eb35'),
('90b4be61-8ea7-465c-aea5-bb6c4c453444', 'Aaron', 'Logan', 'gonzalesbrittany@example.com', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_41.jpg', 1732450880, 0, 0, 0, 0, '3ea9c8d6-fff1-4401-9285-24cdc982839d'),
('918e592f-1d74-48cf-a8b2-d19bef4ccd0d', 'Jacqueline', '', 'jensenjessica@example.net', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_31.jpg', 1732450885, 0, 0, 0, 1732450885, 'b007e8fe-8112-4916-a5d5-2ccc90318609'),
('93beaef5-62e4-42c7-93b5-505517ee2f54', 'Jonathan', 'Williams', 'adamsjose@testsite.org', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_90.jpg', 1732450879, 0, 0, 0, 0, 'af355057-aacc-4a46-946f-e9bb6872b619'),
('94c83510-f374-4a44-a6b9-eab1504a97c9', 'Ashley', 'Kirk', 'greenemily@mydomain.net', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_54.jpg', 1732450879, 0, 0, 0, 1732450879, '2eda6758-1121-44b8-a9c9-641ec5c85458'),
('94e0ff03-f7dd-4494-b2b0-cae637ee3ef5', 'Samantha', '', 'tony25@example.com', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_78.jpg', 1732450887, 0, 1732474828, 0, 1732450887, 'ab64b292-9ed1-489b-a3e4-b47d36a2a735'),
('95a3b134-ef7b-4225-ae86-d79ae903bdfe', 'Christopher', '', 'jennifer90@example.com', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_22.jpg', 1732450883, 0, 0, 0, 1732450883, 'd101422c-79ce-4d2d-83b5-6df75a4f445d'),
('960f1ddf-fe6a-40c3-97c4-039a5dbce9cc', 'Crystal', 'Russell', 'qortiz@example.net', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_36.jpg', 1732450880, 0, 0, 0, 0, 'a8be7215-e815-4912-97cb-bf7bf83b4043'),
('965e1f84-6519-4696-8357-49932450b484', 'Beth', 'Russell', 'jerry86@website.co', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_15.jpg', 1732450879, 0, 0, 0, 0, '1f9b808e-fc1c-49bd-95c5-04f36178b65c'),
('9f679d29-d1fd-4685-8bbc-09e159338018', 'Michelle', 'Wilson', 'holly67@example.net', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_20.jpg', 1732450880, 0, 0, 0, 1732450880, 'bc4cf3e3-74ec-4bcf-be90-2a8cb48e1b0a'),
('a3476af3-39b4-43b5-9f5d-91a4018ca57a', 'Veronica', '', 'rosemiller@example.org', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_26.jpg', 1732450880, 0, 0, 0, 0, '78601d16-c328-4b2e-951c-b1fff97e8cc2'),
('a3be5b8c-e165-48e6-a6cb-5ee1a8d0bf8d', 'Mario', 'Edwards', 'amoore@mydomain.net', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_41.jpg', 1732450879, 0, 0, 0, 1732450879, '1f7eff4d-1d06-4922-ae12-c62d63f95bf0'),
('a6c3e1c4-a902-4d9a-b0f0-513481989993', 'Katherine', 'Green', 'vbraun@example.com', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_64.jpg', 1732450879, 0, 0, 0, 0, '653f5d4e-a75d-49ae-8e64-9dc70db6b1fa'),
('a9ec8b05-c6d6-413b-bda2-8fdc6ed0168a', 'Nicole', 'Jordan', 'tbarnes@example.org', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_22.jpg', 1732450880, 0, 0, 0, 1732450880, '2c82b807-d080-462e-85d1-c02944d7e7eb'),
('aadc638f-5885-4f29-933b-0429bb08c933', 'Patrick', 'Peters', 'alexandersilva@example.org', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_97.jpg', 1732450880, 0, 0, 0, 0, 'ea823268-6bc3-48aa-97da-78a26c2d8e1d'),
('ada8ad0a-d768-4dd4-bedc-64f879d9fc0c', 'Jennifer', '', 'brightbryan@example.net', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_32.jpg', 1732450886, 0, 0, 0, 0, '415ba278-e8e6-4af7-b715-e7073848c86a'),
('aefe0ef4-d278-4aec-810a-dfce2f7497b6', 'Kevin', 'Townsend', 'uescobar@example.org', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_30.jpg', 1732450880, 0, 0, 0, 1732450880, '4c4e9e50-b3c5-4634-9d77-550b29da858b'),
('b2b00d43-6623-4f22-b963-2b8e4ced5d71', 'Kevin', '', 'ashleyspencer@example.net', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_56.jpg', 1732450885, 0, 0, 0, 0, '5012ed0c-a49b-4fbe-8faa-63e8a55391dd'),
('b3d2e494-ecc9-4c00-a6ef-f16505b0a832', 'Alexis', 'Rice', 'jenniferali@example.org', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_83.jpg', 1732450880, 0, 0, 0, 0, 'b077967e-38dd-4b49-b013-e143b3b50ffb'),
('b75f5598-0f05-47b7-acaa-e699b6eadb0d', 'Jacob', 'Nelson', 'lewisrussell@example.com', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_67.jpg', 1732450880, 0, 0, 0, 0, 'e5b6098c-2acd-4ad3-abce-ae651eca9e35'),
('b877e534-d283-4571-a67f-7d7302647543', 'seb', 'møl', 'seb@hotmail.com', 'scrypt:32768:8:1$mab4iyGijDyskYSK$51a0159b47b9bb4fca15cd1d0a6c1f62bb1565682545c20b1d8188160ac178d7de454454fcc735b5ab68c2db458af538dd9e6a9cfd7fc501137286069d633c1f', '', 1732553679, 0, 0, 0, 0, '50553285-532e-4fb4-8647-cc737d7695f5'),
('ba84d94a-5166-4e1a-8550-f55c4f397508', 'Kayla', '', 'garypatrick@example.net', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_99.jpg', 1732450881, 0, 0, 0, 0, 'beba6e92-1b83-49c5-8c67-fbb07d3e563c'),
('bae4dfd9-053c-48d5-81bd-6c9687eaa180', 'Robin', 'Bautista', 'thomassarah@fakemail.io', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_98.jpg', 1732450879, 0, 0, 0, 1732450879, '20153302-6297-4bb4-a13f-24470ff93967'),
('bd93e2eb-3417-4cea-a086-e19639d9b82a', 'Carolyn', 'Travis', 'thomas62@example.net', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_52.jpg', 1732450880, 0, 0, 0, 0, '9b8b2fe9-425e-461f-bcf2-c599083671ad'),
('bfeffc45-8ba8-4459-8bcb-6aee70b158e9', 'Kim', '', 'sandovaleric@example.org', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_19.jpg', 1732450883, 0, 0, 0, 0, '0f76d681-4db7-4e37-a2a6-93174ae343db'),
('c6039322-f0e7-45ed-bd69-47110efd280c', 'Danielle', 'Ingram', 'bradycheryl@fakemail.io', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_33.jpg', 1732450879, 0, 0, 0, 0, '4b0be41e-c04f-4703-8cea-28ca10a0b1b8'),
('c6a0035a-4689-45a6-b3e0-9681ac054415', 'Anna', 'Mclaughlin', 'davidjackson@example.com', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_56.jpg', 1732450880, 0, 0, 0, 0, '1202de27-cef0-4bec-b4c9-d6ead4d3d655'),
('c71ad443-8a7b-4730-980c-005a3dcce423', 'Jeremiah', 'Rodriguez', 'frances14@example.org', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_10.jpg', 1732450880, 0, 0, 0, 0, 'ad45b734-17a1-49af-bc34-d59ee8fa1149'),
('c73cec5b-3841-490a-91ef-cb89c773d412', 'Bryan', 'Lee', 'ricedanielle@example.com', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_53.jpg', 1732450879, 0, 0, 0, 1732450879, 'e7738ff2-832d-44eb-bcc4-0b540bbf7626'),
('c960137a-de16-4fc1-925b-f529fda70410', 'Charles', 'Young', 'kwells@example.com', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_89.jpg', 1732450880, 0, 0, 0, 1732450880, 'c4d4da7b-64ea-4ad1-9eed-ce1247278128'),
('caeefcf8-4c4e-4f7f-8e4e-8fb323dc524d', 'Donald', '', 'matthew70@example.net', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_6.jpg', 1732450881, 0, 0, 0, 0, 'bd533608-a367-42db-a474-0e3df4fd2d53'),
('ccaf241e-d795-4e2e-84d6-25ae93b57c0c', 'Brian', 'Chandler', 'patricia31@example.org', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_83.jpg', 1732450880, 0, 0, 0, 1732450880, '26e33be2-efdf-4336-b564-8c2c7d67618f'),
('d0800f1e-117e-4c77-a446-24ac799a7c54', 'Michelle', '', 'deannayoung@example.com', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_92.jpg', 1732450880, 0, 0, 0, 1732450880, '6af1bbc9-4b51-4551-8a11-8fb8ab43d897'),
('d39866c4-2f6d-4742-8d89-0da6e7d4cc4e', 'Stacy', 'Kirby', 'bkim@example.com', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_26.jpg', 1732450879, 0, 0, 0, 0, '2818518a-292b-4706-90ef-f80bba170fc8'),
('d56511b2-a3fa-4d71-b95a-01630cce8b85', 'Shawn', 'Simmons', 'ashleycrawford@example.com', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_22.jpg', 1732450880, 0, 0, 0, 1732450880, 'a5ffdeee-3cc9-4173-b059-d7c389271593'),
('d60bee74-bd4a-4a37-8ac4-3eacc743e6c3', 'Melissa', 'Steele', 'kristinajones@example.org', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_73.jpg', 1732450880, 0, 0, 0, 0, '346d9c18-557f-4a89-9d2a-56c95e9a0bb0'),
('d737b1e2-1b72-41cd-91e7-320643a10ffc', 'Jacqueline', 'Castillo', 'fcarlson@example.com', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_11.jpg', 1732450880, 0, 0, 0, 0, '364c96f3-366a-41c2-9811-0d5e98e0c624'),
('d74dfee2-88ac-45b5-8a47-3087727f1f9a', 'Anna', 'Preston', 'aoliver@mydomain.net', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_4.jpg', 1732450879, 0, 0, 0, 1732450879, 'b2242438-51f9-45a4-b4e3-df565a186881'),
('daed8c2f-4d25-454c-853b-9207330716f3', 'Nathan', 'Smith', 'joneslarry@testsite.org', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_94.jpg', 1732450879, 0, 0, 0, 0, '49802c9c-6b16-497a-9746-3a8d5ba1c671'),
('db83f475-22fb-4619-8bc0-114b66154f40', 'Bruce', 'Glass', 'wardnathan@testsite.org', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_23.jpg', 1732450879, 0, 0, 0, 1732450879, 'f5715ccb-455b-4cf5-9574-604e97f730f9'),
('db8f3336-51f4-4ff4-8ff3-00ec555c42fa', 'Kevin', 'Gutierrez', 'jasmine57@example.net', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_22.jpg', 1732450880, 0, 0, 0, 1732450880, '2d4a544b-124b-463b-8ec3-dd01c5bb8206'),
('dc42e36d-51d0-4104-8897-2d63719b9ce5', 'Crystal', 'Bowers', 'timothykidd@example.org', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_23.jpg', 1732450880, 0, 0, 0, 1732450880, '6b34013b-878d-4b24-a5ca-74b95ee3175c'),
('ddd4043c-cf3f-4776-8659-13279f8daf23', 'Gary', 'Reed', 'kellycrawford@example.com', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_72.jpg', 1732450880, 0, 0, 0, 0, '43aa48cd-e9a8-496d-953f-82b8f6818421'),
('df3259a5-b9bd-4115-9e06-0c3bf632cc0f', 'Thomas', 'Johnson', 'tinaneal@hotmail.com', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_3.jpg', 1732450879, 0, 0, 0, 1732450879, '6ec03184-9fee-47b2-aa5b-17b65f1d5567'),
('e12ced10-ecc6-4c90-821c-b9b0d5c66750', 'Anthony', 'Mitchell', 'patricia95@example.net', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_45.jpg', 1732450880, 0, 0, 0, 1732450880, 'add58c10-2666-4284-b514-c2b403b2dd4f'),
('e2ce28cc-2810-49a2-8fad-595a689f1ef8', 'Donna', 'Lloyd', 'lruiz@testsite.org', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_80.jpg', 1732450879, 0, 0, 0, 1732450879, 'f82daf06-5c97-4beb-8248-cc9490211ba6'),
('e361aebc-9d3b-48eb-9617-8702c9a8c765', 'Mary', '', 'veronica01@example.org', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_1.jpg', 1732450881, 0, 0, 0, 0, '927b3e3c-11de-4742-9169-054019418404'),
('e4368c79-be20-4741-b5dc-5039de88fb20', 'Laura', 'Parks', 'joneskristy@testsite.org', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_22.jpg', 1732450879, 0, 0, 0, 1732450879, '0159f84b-cf02-47b1-8023-b7eaaff00056'),
('e4c4609c-c2d6-4dda-948b-4327378603fe', 'Kathryn', 'Martinez', 'madeline47@example.com', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_86.jpg', 1732450880, 0, 0, 0, 1732450880, '82df8867-62bb-476c-9967-51f554e723bf'),
('e76536df-f685-4897-a5ca-3632ede72304', 'Joy', '', 'lindseynunez@example.net', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_56.jpg', 1732450884, 0, 0, 0, 0, '43e26137-b93f-4f48-89e2-d317ac36e927'),
('e7ea2776-26d9-48ec-901d-1d0afc1300ae', 'Kyle', '', 'novakkari@example.com', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_68.jpg', 1732450884, 0, 0, 0, 0, '26a9251d-47fc-4840-885d-1b93f5c7c631'),
('ebf4b2a8-106f-4cb0-bed7-a133d1f2c0f0', 'John', 'Restaurant', 'restaurant@fulldemo.com', 'scrypt:32768:8:1$FA67veXGfirj6PHT$ecadbbc93945c8ec5cf5e84e752a571ec2243006a2194af7c0af94a5adbe08cc1d63c00c8cdc231a488231f1c0b29e62800600f4f2d5faa712bca76da0f4081c', 'profile_13.jpg', 1732450879, 0, 0, 0, 1732450879, '293b65ad-69ef-42e8-811b-567c87f7b37e'),
('ec332453-efb2-417d-9821-6abdce39ff42', 'Michael', 'Taylor', 'charleseaton@mydomain.net', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_31.jpg', 1732450879, 0, 0, 0, 1732450879, '1e7880d2-afda-492f-a129-f1feb17c8526'),
('ed8d128a-17d4-4e61-8c55-ca892b5a40bf', 'Shawn', 'Mills', 'ubaker@example.org', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_88.jpg', 1732450880, 0, 0, 0, 1732450880, '4530619c-37ac-44c4-b7d6-b8ba089505cf'),
('f04cca1a-4cff-4c4d-8d65-af1bbf46fa8a', 'Valerie', 'Willis', 'brittany63@example.org', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_63.jpg', 1732450880, 0, 0, 0, 0, '272af9d3-de94-48c1-ac21-619706b03dc6'),
('f08d9328-c2fd-4ae6-9e7b-b34ee2b0d6e0', 'Gilbert', 'Walker', 'kingbilly@hotmail.com', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_57.jpg', 1732450879, 0, 0, 0, 0, 'ff47973d-0cef-4a57-afb9-e80be259e3ed');
INSERT INTO `users` (`user_pk`, `user_name`, `user_last_name`, `user_email`, `user_password`, `user_avatar`, `user_created_at`, `user_deleted_at`, `user_blocked_at`, `user_updated_at`, `user_verified_at`, `user_verification_key`) VALUES
('f1d5423b-0d4b-4557-8339-3f9ade7c2f37', 'Omar', 'Case', 'lisastevens@example.com', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_73.jpg', 1732450880, 0, 0, 0, 1732450880, '4199f12c-0eb7-4a23-9fe6-b8368ef9cdea'),
('f2477c6e-fee2-4339-b3cb-f3160c6e7b53', 'Jose', 'Vasquez', 'cisnerossabrina@website.co', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_16.jpg', 1732450879, 0, 0, 0, 0, '8612e4c8-690e-4b13-a5c6-310463fac2b4'),
('f29ab92c-bb4f-4207-ba60-38862c6828e7', 'Scott', '', 'guzmanbrittany@example.net', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_5.jpg', 1732450885, 0, 0, 0, 1732450885, '8c24dc65-2d03-4530-bb68-a31dc0866832'),
('f36cb821-b003-4615-baa2-7fd575d86505', 'Edward', 'Nguyen', 'adeleon@mydomain.net', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_51.jpg', 1732450879, 0, 0, 0, 0, 'b0dad13c-7eb9-4c8f-b4b4-2f1b7647de3b'),
('f3cf660f-f8b2-482b-8886-1357d0f01636', 'Lori', '', 'zcontreras@example.net', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_12.jpg', 1732450883, 0, 0, 0, 1732450883, '66b88da0-8d99-4ebb-be75-ac9909f7b2ed'),
('f429f34e-6ecb-47ed-a726-c5cc6999a2f7', 'Carol', '', 'elyons@example.net', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_89.jpg', 1732450882, 0, 0, 0, 1732450882, '2c022878-341e-451f-95bb-f98f3c64b036'),
('f6124166-c979-4390-a398-169a43283fb2', 'Jeffrey', '', 'mistypaul@example.com', 'scrypt:32768:8:1$H45meI6SAXMxgk2m$57a9129e83574944d118ce9ede16c327c6be706b0c4889144542b2509d602db3e04001f5f47b381d78ca1580a7d51d961b309e2d956ab54447ecc35c210bffa6', 'profile_59.jpg', 1732450883, 0, 0, 0, 0, '8f460278-0c76-47a7-95bb-33f4aae64a32'),
('f87c958e-1c8a-499c-a853-543d95dc19ea', 'Michael', 'Brown', 'sarahstone@hotmail.com', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_78.jpg', 1732450879, 0, 0, 0, 0, '62bbc32c-3d02-4266-ac30-c6e622703be0'),
('f949c294-864b-4d81-a87b-bfbbfef2736d', 'John', 'Ross', 'gomezmonica@testsite.org', 'scrypt:32768:8:1$iKQGwwrWK4T12Fft$5f4847a4a2827f989e13a2f6be5ed5e6a1d29fd00269bf82d4234ad88d1f9c4d592e63d3e272b4809d9f828c59581d2f220fcb78184fb506c5c3b227224dde1d', 'profile_66.jpg', 1732450879, 0, 0, 0, 1732450879, '398ca2b7-a8b5-4811-a8ce-40de396abc48'),
('fe12340a-ac4c-4055-a4d0-f55eda7d97df', 'Danny', 'Thompson', 'watsonluis@example.com', 'scrypt:32768:8:1$wCkpolow02cCItUw$601e18b7d8f3c0bb465012bbc456021efd0a9293cf44c85b4f482aa66e855a71e5604da6d9d4a6bb7c3752c6372f73450fb17c8184d5957fdb1d53c8b51687b5', 'profile_87.jpg', 1732450880, 0, 0, 0, 1732450880, 'a1399c44-9109-4c83-b204-6467294e578c');

-- --------------------------------------------------------

--
-- Struktur-dump for tabellen `users_roles`
--

CREATE TABLE `users_roles` (
  `user_role_user_fk` char(36) NOT NULL,
  `user_role_role_fk` char(36) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Data dump for tabellen `users_roles`
--

INSERT INTO `users_roles` (`user_role_user_fk`, `user_role_role_fk`) VALUES
('6ff79666-4e24-4774-8189-10447043af54', '16fd2706-8baf-433b-82eb-8c7fada847da'),
('000d6183-bfe1-49e6-af87-d386990dcf14', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('01cb4104-b442-4460-bad7-a9694d366858', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('02bb1089-ed87-44c9-8b5f-3cb252e5e22a', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('072b131d-9ed0-49fc-9426-7511b5eddc12', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('0d2c931d-39b3-42db-af5d-d048a541c9ff', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('0ff320d4-a617-45f0-a241-52987fa0a421', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('123d5c47-e948-4ce5-b299-acc4133bf1cc', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('145b6d1a-eeef-40e2-a43f-f1bdb2faecb5', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('19bf720e-9319-4455-beb1-79968fbfac09', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('1b56c196-9cf1-43c7-a658-eafd6711850e', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('20a40f63-de41-430c-8693-90efb4e958dc', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('2672b12c-01a5-43a8-8f78-d6eb571489bb', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('27765da5-bc36-49bb-8f20-ca42bd9d79c2', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('3bcfd481-160e-45fb-ac2c-abd010342562', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('3c562f8f-6802-46eb-a306-e252924c048a', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('3e4ff5d1-fbf0-4259-beac-b6ba725fc0db', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('42630eb6-8c52-4bf0-99f4-3c6bfb535a6b', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('4aebd108-8ef2-42e6-a202-b15143f721c5', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('53fc94f7-6c2d-4b04-a27f-7bd915fd30aa', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('553a0df0-b9db-435b-a65a-55bc572020df', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('5591d016-399e-4784-8c63-150e9e1694c4', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('5ea8d9eb-a906-44fd-86db-7e2a414f9f1e', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('6ae116a3-46b7-47b1-b4eb-4732acaf28e4', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('706fa6cd-54ae-4792-9167-47fdbe5613a9', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('71ff21f8-118a-489e-9e70-fca71927dede', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('7947a80d-a4ae-418e-8f6e-52be069e4fb1', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('8500227e-cd04-4329-9c2c-2f89cb72c37a', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('855d6b52-7f4d-4513-a07a-f7c959831efa', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('86333921-c90c-4e80-880b-1a6a346f8f32', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('86e6f3bc-e51f-4bfa-9877-d089e5741607', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('8a5870c7-11e2-4f61-9089-7845d41cd633', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('8d4a27c5-a8da-441e-b296-433076ea94e7', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('8ec09a4f-368a-4841-a1dc-905d4fd72cbc', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('918e592f-1d74-48cf-a8b2-d19bef4ccd0d', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('94e0ff03-f7dd-4494-b2b0-cae637ee3ef5', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('95a3b134-ef7b-4225-ae86-d79ae903bdfe', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('a3476af3-39b4-43b5-9f5d-91a4018ca57a', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('ada8ad0a-d768-4dd4-bedc-64f879d9fc0c', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('b2b00d43-6623-4f22-b963-2b8e4ced5d71', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('ba84d94a-5166-4e1a-8550-f55c4f397508', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('bfeffc45-8ba8-4459-8bcb-6aee70b158e9', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('caeefcf8-4c4e-4f7f-8e4e-8fb323dc524d', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('d0800f1e-117e-4c77-a446-24ac799a7c54', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('e361aebc-9d3b-48eb-9617-8702c9a8c765', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('e76536df-f685-4897-a5ca-3632ede72304', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('e7ea2776-26d9-48ec-901d-1d0afc1300ae', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('ebf4b2a8-106f-4cb0-bed7-a133d1f2c0f0', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('f29ab92c-bb4f-4207-ba60-38862c6828e7', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('f3cf660f-f8b2-482b-8886-1357d0f01636', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('f429f34e-6ecb-47ed-a726-c5cc6999a2f7', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('f6124166-c979-4390-a398-169a43283fb2', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('034f515f-c83a-4c53-946c-1e1f2a4684aa', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('06f4712c-8054-4b52-9342-615099fb67f2', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('087df979-bcff-4ef1-9c30-f968957a16e8', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('0cd80f30-f2cb-4f61-aa0c-8ec09be06789', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('0f9c002a-5bb4-4003-8309-eb72f0c06a0b', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('1efb3331-6370-4cd6-942d-296d6cf303b2', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('1fe1243e-3dc3-45ad-bb91-f7e7dabafea4', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('2480f42c-a0a7-497c-b68b-86a06d8fb320', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('263d6b2a-78b1-4425-9d80-05f954c736f4', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('26f98772-7157-4dd4-9e4e-3480787c6e44', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('2fe7d474-3438-4456-9959-da9e1037c2c4', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('30d7b56b-078b-438d-800c-b5bea795620a', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('31d35390-e06b-4c17-bf1a-f2a845e2c14f', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('3b2615ee-fbb6-4446-a5a2-fe23b0191ae1', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('4218788d-03b7-4812-bd7d-31c8859e92d8', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('42ea150f-fb86-4602-8ecb-c47340ac031b', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('492ce812-b3bd-4aea-a919-612c483478c5', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('5ac06980-7eaa-423e-9503-fb63a50d232d', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('5ea6e922-bd5d-43be-9592-eb468bb15e2e', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('627b3117-a63c-4a8c-a294-949fbf5e5833', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('6b7df1fa-0e28-489a-80e3-e020112a5779', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('6c14f210-d22f-4b39-b842-7bf683965f5d', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('6f5d5fcd-d791-40a3-9be6-8999d2319a57', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('732749ca-ca6e-4ef6-8204-53f37724745d', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('7acd8943-1667-4982-9b1b-fa974cac232b', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('7b30040e-cd2b-491b-b77e-ef971f44c495', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('7d151992-e908-4bfc-acdb-76e2e86c06e6', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('7f73d660-346e-4b50-8759-8e4fea2370a9', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('805148b4-f629-4647-8ddd-0d8a338715ea', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('8466b24c-eef5-48c9-926e-939d4e9aff0b', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('896a78f7-c481-4503-8a2b-6b13a779a589', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('8b867f65-4dc4-481c-ae90-e5da1fedd3ac', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('93beaef5-62e4-42c7-93b5-505517ee2f54', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('94c83510-f374-4a44-a6b9-eab1504a97c9', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('965e1f84-6519-4696-8357-49932450b484', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('a3be5b8c-e165-48e6-a6cb-5ee1a8d0bf8d', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('a6c3e1c4-a902-4d9a-b0f0-513481989993', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('bae4dfd9-053c-48d5-81bd-6c9687eaa180', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('c6039322-f0e7-45ed-bd69-47110efd280c', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('c73cec5b-3841-490a-91ef-cb89c773d412', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('d39866c4-2f6d-4742-8d89-0da6e7d4cc4e', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('d74dfee2-88ac-45b5-8a47-3087727f1f9a', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('daed8c2f-4d25-454c-853b-9207330716f3', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('db83f475-22fb-4619-8bc0-114b66154f40', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('df3259a5-b9bd-4115-9e06-0c3bf632cc0f', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('e2ce28cc-2810-49a2-8fad-595a689f1ef8', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('e4368c79-be20-4741-b5dc-5039de88fb20', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('ec332453-efb2-417d-9821-6abdce39ff42', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('f08d9328-c2fd-4ae6-9e7b-b34ee2b0d6e0', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('f2477c6e-fee2-4339-b3cb-f3160c6e7b53', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('f36cb821-b003-4615-baa2-7fd575d86505', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('f87c958e-1c8a-499c-a853-543d95dc19ea', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('f949c294-864b-4d81-a87b-bfbbfef2736d', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('09ee98e0-0535-475c-83e9-12c570339faf', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('0ac52fca-bdc9-4fb4-8588-e92c59d57fef', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('10d07662-611a-4d75-9c64-9fc6dc767439', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('133d2d8a-5c1d-4c5e-b693-dc26453b84d9', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('21631177-8334-43be-8529-cdf579273af0', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('2bee73fa-3462-42ac-8f75-dc38b8e0757e', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('2db20c77-236e-459a-9ab3-2f710f4b9ef6', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('31b83b10-45d7-4b57-acd2-825684e778b6', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('3fd0a1f9-d596-4850-88de-b6e490b73bd8', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('445204b1-984f-4cf4-9eb5-00b07ea2b5b6', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('453772c3-a9ba-4c11-bcda-0287d8324dde', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('480f1c22-47e0-4072-ac13-2d13a64234b9', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('48c6351a-9e77-486d-a70a-908e7ea7891e', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('53194d76-d657-4238-9580-1e1294eda815', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('540a6c6d-ef81-490c-837b-02de30eb2d9f', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('585d1a54-b184-4a70-acf2-d6dfaf182100', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('5e70ce28-3ec7-476a-94a4-772796e29c4a', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('5f0a69f1-63cd-4590-b006-ee653c960889', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('5fcb29ef-fe4d-429e-8da1-a1f24baf27a8', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('61a34414-1156-4a61-9ba3-121bc0095978', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('640e2ffb-c15d-402c-9701-7b8d1751a13a', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('6f1049ea-0957-4fef-ae67-0392099f437e', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('72ec3f92-2b59-48c3-bd25-acfd24a6c7c6', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('82b94871-7988-456f-ad7c-f0dbff18fae2', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('843628c8-7e27-4e21-bfed-421228dd6f22', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('8d8fadbb-5824-474b-aba8-c680aa3c3a41', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('8f43ca25-9758-4b4a-80f2-e1e982fed054', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('90b4be61-8ea7-465c-aea5-bb6c4c453444', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('960f1ddf-fe6a-40c3-97c4-039a5dbce9cc', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('9f679d29-d1fd-4685-8bbc-09e159338018', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('a9ec8b05-c6d6-413b-bda2-8fdc6ed0168a', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('aadc638f-5885-4f29-933b-0429bb08c933', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('aefe0ef4-d278-4aec-810a-dfce2f7497b6', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('b3d2e494-ecc9-4c00-a6ef-f16505b0a832', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('b75f5598-0f05-47b7-acaa-e699b6eadb0d', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('b877e534-d283-4571-a67f-7d7302647543', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('bd93e2eb-3417-4cea-a086-e19639d9b82a', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('c6a0035a-4689-45a6-b3e0-9681ac054415', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('c71ad443-8a7b-4730-980c-005a3dcce423', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('c960137a-de16-4fc1-925b-f529fda70410', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('ccaf241e-d795-4e2e-84d6-25ae93b57c0c', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('d56511b2-a3fa-4d71-b95a-01630cce8b85', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('d60bee74-bd4a-4a37-8ac4-3eacc743e6c3', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('d737b1e2-1b72-41cd-91e7-320643a10ffc', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('db8f3336-51f4-4ff4-8ff3-00ec555c42fa', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('dc42e36d-51d0-4104-8897-2d63719b9ce5', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('ddd4043c-cf3f-4776-8659-13279f8daf23', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('e12ced10-ecc6-4c90-821c-b9b0d5c66750', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('e4c4609c-c2d6-4dda-948b-4327378603fe', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('ed8d128a-17d4-4e61-8c55-ca892b5a40bf', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('f04cca1a-4cff-4c4d-8d65-af1bbf46fa8a', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('f1d5423b-0d4b-4557-8339-3f9ade7c2f37', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('fe12340a-ac4c-4055-a4d0-f55eda7d97df', 'f47ac10b-58cc-4372-a567-0e02b2c3d479');

--
-- Begrænsninger for dumpede tabeller
--

--
-- Indeks for tabel `items`
--
ALTER TABLE `items`
  ADD PRIMARY KEY (`item_pk`),
  ADD KEY `item_user_fk` (`item_user_fk`);

--
-- Indeks for tabel `roles`
--
ALTER TABLE `roles`
  ADD PRIMARY KEY (`role_pk`),
  ADD UNIQUE KEY `role_name` (`role_name`);

--
-- Indeks for tabel `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`user_pk`),
  ADD UNIQUE KEY `user_email` (`user_email`);

--
-- Indeks for tabel `users_roles`
--
ALTER TABLE `users_roles`
  ADD PRIMARY KEY (`user_role_user_fk`,`user_role_role_fk`),
  ADD KEY `user_role_role_fk` (`user_role_role_fk`);

--
-- Begrænsninger for dumpede tabeller
--

--
-- Begrænsninger for tabel `items`
--
ALTER TABLE `items`
  ADD CONSTRAINT `items_ibfk_1` FOREIGN KEY (`item_user_fk`) REFERENCES `users` (`user_pk`) ON DELETE CASCADE ON UPDATE RESTRICT;

--
-- Begrænsninger for tabel `users_roles`
--
ALTER TABLE `users_roles`
  ADD CONSTRAINT `users_roles_ibfk_1` FOREIGN KEY (`user_role_user_fk`) REFERENCES `users` (`user_pk`) ON DELETE CASCADE ON UPDATE RESTRICT,
  ADD CONSTRAINT `users_roles_ibfk_2` FOREIGN KEY (`user_role_role_fk`) REFERENCES `roles` (`role_pk`) ON DELETE CASCADE ON UPDATE RESTRICT;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
