-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Vært: mysql
-- Genereringstid: 01. 12 2024 kl. 20:53:19
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
  `item_image_1` varchar(50) DEFAULT NULL,
  `item_image_2` varchar(50) DEFAULT NULL,
  `item_image_3` varchar(50) DEFAULT NULL,
  `item_created_at` int UNSIGNED DEFAULT NULL,
  `item_deleted_at` int UNSIGNED DEFAULT NULL,
  `item_blocked_at` int UNSIGNED DEFAULT NULL,
  `item_updated_at` int UNSIGNED DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Data dump for tabellen `items`
--

INSERT INTO `items` (`item_pk`, `item_user_fk`, `item_title`, `item_price`, `item_image_1`, `item_image_2`, `item_image_3`, `item_created_at`, `item_deleted_at`, `item_blocked_at`, `item_updated_at`) VALUES
('06cc1565-4bf7-435e-b551-91ebdacbf01c', '305b04e6-41c5-4826-8188-6380f70ab1c6', 'Frittata', 720.53, 'dish_20.jpg', 'dish_20.jpg', 'dish_20.jpg', 1733007675, 0, 0, 0),
('092c467a-bc95-4aa1-8d2e-83819a121034', '695e32c5-0fa2-44f3-985a-80a6c7a62883', 'Gnocchi', 564.63, 'dish_55.jpg', 'dish_55.jpg', 'dish_55.jpg', 1733007675, 0, 0, 0),
('10e57f27-6a67-4914-a0c6-2e6b5d8c32dc', '1f0f49ec-0d7e-4274-a697-e4c2f6aaa64e', 'Cannelloni', 645.42, 'dish_57.jpg', 'dish_57.jpg', 'dish_57.jpg', 1733007675, 0, 0, 0),
('1593c35b-ed86-4207-ae05-fcaf1efeba3d', 'fb2f4334-fd7a-4089-adc1-37d099bf46d5', 'Beef Wellington', 658.85, 'dish_11.jpg', 'dish_11.jpg', 'dish_11.jpg', 1733007675, 0, 0, 0),
('25ea865e-3b47-4eff-8ff5-1ddbcd86c347', '305b04e6-41c5-4826-8188-6380f70ab1c6', 'Dim Sum', 792.57, 'dish_88.jpg', 'dish_88.jpg', 'dish_88.jpg', 1733007675, 0, 0, 0),
('29de89af-991a-48ac-8ca0-b67cb9d39be9', 'fd64c6a1-5d33-4e69-8371-304004e5c349', 'Ragu', 676.30, 'dish_44.jpg', 'dish_44.jpg', 'dish_44.jpg', 1733007675, 0, 0, 0),
('300335e0-1d2a-43ac-bb29-418c7cf39860', '5213ea63-5893-48d8-81e0-9886b7f7769a', 'Tofu Stir Fry', 685.17, 'dish_78.jpg', 'dish_78.jpg', 'dish_78.jpg', 1733007675, 0, 0, 0),
('31524fa4-5dc6-4641-beb9-9d378d714b42', '49966367-0a9e-49e3-a5b4-15800f56ed2e', 'Gnocchi', 725.29, 'dish_79.jpg', 'dish_79.jpg', 'dish_79.jpg', 1733007675, 0, 0, 0),
('35c09f73-18ad-4711-84f9-628d19536132', '14cb5887-f539-42be-8f0d-06485866232b', 'Schnitzel', 694.70, 'dish_29.jpg', 'dish_29.jpg', 'dish_29.jpg', 1733007675, 0, 0, 0),
('3760dc3c-b2f2-4a84-a7c6-a8e377091a8e', '305b04e6-41c5-4826-8188-6380f70ab1c6', 'Tom Yum Soup', 651.69, 'dish_31.jpg', 'dish_31.jpg', 'dish_31.jpg', 1733007675, 0, 0, 0),
('3d033773-15d4-49cf-b0f7-ef632ea1d794', '5213ea63-5893-48d8-81e0-9886b7f7769a', 'Lasagna', 517.87, 'dish_6.jpg', 'dish_6.jpg', 'dish_6.jpg', 1733007675, 0, 0, 0),
('3da623f5-0807-476a-9adb-d0001e42ec27', '49966367-0a9e-49e3-a5b4-15800f56ed2e', 'Biryani', 911.33, 'dish_96.jpg', 'dish_96.jpg', 'dish_96.jpg', 1733007675, 0, 0, 0),
('3e01d79a-ff7e-48ca-9d00-dc28dc13a90a', '14cb5887-f539-42be-8f0d-06485866232b', 'Baked Ziti', 849.98, 'dish_81.jpg', 'dish_81.jpg', 'dish_81.jpg', 1733007675, 0, 0, 0),
('42225aff-94f5-4519-bbd8-caf4dbb99222', 'b3991867-310f-437b-a5ab-177c33be8c46', 'Cordon Bleu', 862.35, 'dish_33.jpg', 'dish_33.jpg', 'dish_33.jpg', 1733007675, 0, 0, 0),
('457f085a-b0de-49db-970b-4c75744a3e26', '49966367-0a9e-49e3-a5b4-15800f56ed2e', 'Cannelloni', 871.30, 'dish_71.jpg', 'dish_71.jpg', 'dish_71.jpg', 1733007675, 0, 0, 0),
('4754387b-7a73-465b-98af-be5d65215545', '695e32c5-0fa2-44f3-985a-80a6c7a62883', 'Bulgogi', 539.70, 'dish_94.jpg', 'dish_94.jpg', 'dish_94.jpg', 1733007675, 0, 0, 0),
('4be5fe3c-467f-42d6-9bbc-a79fc7daf320', '5213ea63-5893-48d8-81e0-9886b7f7769a', 'Tom Yum Soup', 522.65, 'dish_91.jpg', 'dish_91.jpg', 'dish_91.jpg', 1733007675, 0, 0, 0),
('54a3651b-b7a3-4349-8f1f-55f6950331d4', '695e32c5-0fa2-44f3-985a-80a6c7a62883', 'Beef Wellington', 593.12, 'dish_21.jpg', 'dish_21.jpg', 'dish_21.jpg', 1733007675, 0, 0, 0),
('55d704aa-546f-4adb-97ae-c8b4ae1e6772', 'fb2f4334-fd7a-4089-adc1-37d099bf46d5', 'Beef Brisket', 626.32, 'dish_48.jpg', 'dish_48.jpg', 'dish_48.jpg', 1733007675, 0, 0, 0),
('560165bd-8162-4ec2-9079-646eece7e428', '1f0f49ec-0d7e-4274-a697-e4c2f6aaa64e', 'Chicken Tikka Masala', 799.60, 'dish_80.jpg', 'dish_80.jpg', 'dish_80.jpg', 1733007675, 0, 0, 0),
('59dfb9ff-fa8c-4959-975f-08e7f44a5afb', 'fb2f4334-fd7a-4089-adc1-37d099bf46d5', 'Caesar Salad', 925.63, 'dish_21.jpg', 'dish_21.jpg', 'dish_21.jpg', 1733007675, 0, 0, 0),
('5ecebbc7-4157-4cbb-b17d-41fb75a0178a', 'fd64c6a1-5d33-4e69-8371-304004e5c349', 'Yakitori', 937.78, 'dish_58.jpg', 'dish_58.jpg', 'dish_58.jpg', 1733007675, 0, 0, 0),
('61ae7c67-f6fb-48bb-8984-147bbb342a68', '695e32c5-0fa2-44f3-985a-80a6c7a62883', 'Empanadas', 562.78, 'dish_4.jpg', 'dish_4.jpg', 'dish_4.jpg', 1733007675, 0, 0, 0),
('6363fbb3-b6cb-483e-bbe3-c71f00da650c', '49966367-0a9e-49e3-a5b4-15800f56ed2e', 'Chicken Tikka Masala', 945.03, 'dish_44.jpg', 'dish_44.jpg', 'dish_44.jpg', 1733007675, 0, 0, 0),
('645ca6c4-4b99-43a5-abe4-7ed44073c739', '5213ea63-5893-48d8-81e0-9886b7f7769a', 'Paella Valenciana', 695.72, 'dish_5.jpg', 'dish_5.jpg', 'dish_5.jpg', 1733007675, 0, 0, 0),
('649c86d2-95b1-43fb-b6c8-d9bd4e180166', 'a6ca214e-d3c5-4a85-a948-d2bdb0becfaa', 'Pho', 844.38, 'dish_1.jpg', 'dish_1.jpg', 'dish_1.jpg', 1733007675, 0, 0, 0),
('67c93768-a61c-4517-8ffd-b82747babd2a', '695e32c5-0fa2-44f3-985a-80a6c7a62883', 'Lasagna', 503.52, 'dish_49.jpg', 'dish_49.jpg', 'dish_49.jpg', 1733007675, 0, 0, 0),
('6819e8a6-1006-4c87-9616-626a088e7704', '305b04e6-41c5-4826-8188-6380f70ab1c6', 'Caesar Salad', 815.40, 'dish_33.jpg', 'dish_33.jpg', 'dish_33.jpg', 1733007675, 0, 0, 0),
('6a9899e1-3631-49a9-97d2-86e3cdad6aff', 'a6ca214e-d3c5-4a85-a948-d2bdb0becfaa', 'Fish and Chips', 547.90, 'dish_50.jpg', 'dish_50.jpg', 'dish_50.jpg', 1733007675, 0, 0, 0),
('78dac3a0-5d7a-4223-a069-a51ef120379f', '1f0f49ec-0d7e-4274-a697-e4c2f6aaa64e', 'Souvlaki', 713.52, 'dish_10.jpg', 'dish_10.jpg', 'dish_10.jpg', 1733007675, 0, 0, 0),
('7ff5f1dc-f32b-471a-a77a-05d131e8563d', 'fd64c6a1-5d33-4e69-8371-304004e5c349', 'Ahi Poke', 586.69, 'dish_21.jpg', 'dish_21.jpg', 'dish_21.jpg', 1733007675, 0, 0, 0),
('7ffd227f-b8a9-46cc-b937-a59db79ffe7b', '14cb5887-f539-42be-8f0d-06485866232b', 'Bulgogi', 976.47, 'dish_97.jpg', 'dish_97.jpg', 'dish_97.jpg', 1733007675, 0, 0, 0),
('838a4db5-7b10-40c6-b8f5-626bbd2a1822', '14cb5887-f539-42be-8f0d-06485866232b', 'Ahi Poke', 659.04, 'dish_70.jpg', 'dish_70.jpg', 'dish_70.jpg', 1733007675, 0, 0, 0),
('8b1a9560-0df1-43d3-b6ed-10bfa70e2cd6', '695e32c5-0fa2-44f3-985a-80a6c7a62883', 'Pesto Pasta', 688.27, 'dish_89.jpg', 'dish_89.jpg', 'dish_89.jpg', 1733007675, 0, 0, 0),
('8b35134b-f7a8-4fb3-b39e-9951da833ce3', '49966367-0a9e-49e3-a5b4-15800f56ed2e', 'Samosas', 505.74, 'dish_4.jpg', 'dish_4.jpg', 'dish_4.jpg', 1733007675, 0, 0, 0),
('8c6b13a7-6544-4163-905b-e8ea3d2ae97f', 'fb2f4334-fd7a-4089-adc1-37d099bf46d5', 'Hot Pot', 892.24, 'dish_55.jpg', 'dish_55.jpg', 'dish_55.jpg', 1733007675, 0, 0, 0),
('8e031ca1-415d-46e8-be40-aad8a4b867bb', 'fd64c6a1-5d33-4e69-8371-304004e5c349', 'Tom Yum Soup', 872.28, 'dish_54.jpg', 'dish_54.jpg', 'dish_54.jpg', 1733007675, 0, 0, 0),
('90919393-14cb-4d20-90e4-09c484c3e39f', '14cb5887-f539-42be-8f0d-06485866232b', 'Ragu', 767.80, 'dish_8.jpg', 'dish_8.jpg', 'dish_8.jpg', 1733007675, 0, 0, 0),
('91c9441d-3056-45d7-88b6-611bb11c9e52', 'b3991867-310f-437b-a5ab-177c33be8c46', 'Chilaquiles', 618.69, 'dish_80.jpg', 'dish_80.jpg', 'dish_80.jpg', 1733007675, 0, 0, 0),
('931ce5c6-8356-4ddb-90da-36e91722edbb', '1f0f49ec-0d7e-4274-a697-e4c2f6aaa64e', 'Beef Wellington', 587.80, 'dish_30.jpg', 'dish_30.jpg', 'dish_30.jpg', 1733007675, 0, 0, 0),
('a5603d6e-a24a-4a2a-bf05-c4b801f3f01a', 'fb2f4334-fd7a-4089-adc1-37d099bf46d5', 'Mango Sticky Rice', 901.64, 'dish_13.jpg', 'dish_13.jpg', 'dish_13.jpg', 1733007675, 0, 0, 0),
('a5c2cabe-c352-4177-94b0-43fdc0bf4ad2', 'fd64c6a1-5d33-4e69-8371-304004e5c349', 'Chicken Parmesan', 823.71, 'dish_65.jpg', 'dish_65.jpg', 'dish_65.jpg', 1733007675, 0, 0, 0),
('af3c0dc9-7715-49c8-844b-0d6bdbf0a46d', '1f0f49ec-0d7e-4274-a697-e4c2f6aaa64e', 'Tiramisu', 642.82, 'dish_17.jpg', 'dish_17.jpg', 'dish_17.jpg', 1733007675, 0, 0, 0),
('b5195569-ece4-4f9d-bc3b-38fdd67b412b', 'a6ca214e-d3c5-4a85-a948-d2bdb0becfaa', 'Dim Sum', 975.49, 'dish_19.jpg', 'dish_19.jpg', 'dish_19.jpg', 1733007675, 0, 0, 0),
('b7fbdf43-fa9d-44bd-b911-e040f3bcf412', 'b3991867-310f-437b-a5ab-177c33be8c46', 'Hot Pot', 528.96, 'dish_56.jpg', 'dish_56.jpg', 'dish_56.jpg', 1733007675, 0, 0, 0),
('bac6b629-cf6b-4b63-b675-14fe810555e5', '305b04e6-41c5-4826-8188-6380f70ab1c6', 'Ratatouille', 769.62, 'dish_33.jpg', 'dish_33.jpg', 'dish_33.jpg', 1733007675, 0, 1733086072, 1733086072),
('c472027b-aed9-4cb4-9197-a40250e2cd07', '14cb5887-f539-42be-8f0d-06485866232b', 'Caesar Salad', 514.08, 'dish_15.jpg', 'dish_15.jpg', 'dish_15.jpg', 1733007675, 0, 0, 0),
('c514af30-72fe-4a72-adb0-94aee896b7d6', 'b3991867-310f-437b-a5ab-177c33be8c46', 'Bibimbap', 650.06, 'dish_75.jpg', 'dish_75.jpg', 'dish_75.jpg', 1733007675, 0, 0, 0),
('c9c176c7-6b41-4c50-9a7a-8f15c5fa3ae9', 'a6ca214e-d3c5-4a85-a948-d2bdb0becfaa', 'Samosas', 993.39, 'dish_48.jpg', 'dish_48.jpg', 'dish_48.jpg', 1733007675, 0, 0, 0),
('d4da28ed-aec4-492a-9ad4-aa624752b6a3', '305b04e6-41c5-4826-8188-6380f70ab1c6', 'Souvlaki', 904.75, 'dish_67.jpg', 'dish_67.jpg', 'dish_67.jpg', 1733007675, 0, 0, 0),
('d7327c91-76a9-4527-9f67-d273bd16bb25', '1f0f49ec-0d7e-4274-a697-e4c2f6aaa64e', 'Sweet and Sour Pork', 663.49, 'dish_59.jpg', 'dish_59.jpg', 'dish_59.jpg', 1733007675, 0, 0, 0),
('d9f09058-639d-423a-9f9b-bae9fcb5e791', 'fd64c6a1-5d33-4e69-8371-304004e5c349', 'Gnocchi', 841.73, 'dish_30.jpg', 'dish_30.jpg', 'dish_30.jpg', 1733007675, 0, 0, 0),
('dc30e133-dedd-45a4-aef4-693921166ff3', 'fb2f4334-fd7a-4089-adc1-37d099bf46d5', 'Lamb Tagine', 813.02, 'dish_78.jpg', 'dish_78.jpg', 'dish_78.jpg', 1733007675, 0, 0, 0),
('e1fd48f7-8e07-42a6-9568-122468bb6863', 'b3991867-310f-437b-a5ab-177c33be8c46', 'Tandoori Chicken', 877.14, 'dish_47.jpg', 'dish_47.jpg', 'dish_47.jpg', 1733007675, 0, 0, 0),
('e95408f2-ee27-4a47-9e04-739c48c4eaa7', 'b3991867-310f-437b-a5ab-177c33be8c46', 'Clafoutis', 690.51, 'dish_100.jpg', 'dish_100.jpg', 'dish_100.jpg', 1733007675, 0, 0, 0),
('ea6f32b9-a216-41f0-9ec8-8f1f808a97d2', 'a6ca214e-d3c5-4a85-a948-d2bdb0becfaa', 'Peking Duck', 702.81, 'dish_81.jpg', 'dish_81.jpg', 'dish_81.jpg', 1733007675, 0, 0, 0),
('f1671563-85cf-45b2-972b-6934333c2642', '5213ea63-5893-48d8-81e0-9886b7f7769a', 'Chicken Katsu', 804.41, 'dish_90.jpg', 'dish_90.jpg', 'dish_90.jpg', 1733007675, 0, 0, 0),
('f8ba5b75-9d2b-48bf-8336-d4d2936729d2', '5213ea63-5893-48d8-81e0-9886b7f7769a', 'Masala Dosa', 634.18, 'dish_85.jpg', 'dish_85.jpg', 'dish_85.jpg', 1733007675, 0, 0, 0),
('f8ddea7d-67e2-4dbc-ac3f-9dda31852a98', '49966367-0a9e-49e3-a5b4-15800f56ed2e', 'Roti', 984.53, 'dish_4.jpg', 'dish_4.jpg', 'dish_4.jpg', 1733007675, 0, 0, 0),
('fd6c593f-732e-4a6a-8b61-9cd9d0871bef', 'a6ca214e-d3c5-4a85-a948-d2bdb0becfaa', 'Chicken Katsu', 727.51, 'dish_78.jpg', 'dish_78.jpg', 'dish_78.jpg', 1733007675, 0, 0, 0);

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
  `user_verification_key` char(36) DEFAULT NULL,
  `user_reset_password_key` char(36) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Data dump for tabellen `users`
--

INSERT INTO `users` (`user_pk`, `user_name`, `user_last_name`, `user_email`, `user_password`, `user_avatar`, `user_created_at`, `user_deleted_at`, `user_blocked_at`, `user_updated_at`, `user_verified_at`, `user_verification_key`, `user_reset_password_key`) VALUES
('14cb5887-f539-42be-8f0d-06485866232b', 'Sandra', '', 'whancock@example.org', 'scrypt:32768:8:1$ZH853zn95F6Eu189$9d00a9af581c5f0a46d229d6eb8eda889d25c74278e51125e9805c975d815c621925cecfef6fa4c94788f02a7a445f8d767ee0e213f0ecfa44b549fbb952bda6', 'profile_99.jpg', 1733007675, 0, 0, 0, 0, '4eea7240-ad7d-48a2-b611-b2c6d8b6ab10', ''),
('17394923-34ac-4eb3-bd71-6837f308b15e', 'John', 'Restaurant', 'restaurant@fulldemo.com', 'scrypt:32768:8:1$ftsnyGHYICX0cprc$5409dd0e71f0c3d2ff9ce88c37d159a57b9f348f7bd4cbfbc268c7dbfcc7d0bbdd6626356f7a8c3b64393dc0aa05587bcbe33ad305166b6a64a46d13ec7edffc', 'profile_13.jpg', 1733007675, 0, 0, 1733086079, 1733007675, '424026ff-fef4-4a13-871c-561face83014', ''),
('1df25c60-06d7-4ea1-89db-eec833cbe518', 'Leslie', 'Harper', 'rpowell@website.co', 'scrypt:32768:8:1$ZvDeB1hRHqNZuYHD$9a22c9a790319f357307033d69b9ef637d6e86195c76dc798a7c6f242850f78dbd1a1771640817f7e944c4067f3a5a79b6183547ca28e3215ff095462c4d528a', 'profile_82.jpg', 1733007675, 0, 0, 0, 1733007675, 'beca7412-985c-4e4c-ae62-857f619c0e32', ''),
('1f0f49ec-0d7e-4274-a697-e4c2f6aaa64e', 'Laura', '', 'maryboyer@example.net', 'scrypt:32768:8:1$m2fhEZYjZHtcAgVE$7fa01965f27519f458ede61a151246cc01738359fe783439f420eb551f5ce55e6079929ebd120bb555c031d36d1373d3a33e1c1c41be9e13c68324a51a52d74d', 'profile_71.jpg', 1733007675, 0, 0, 1733008325, 0, '4e90fa4e-a06c-407d-84aa-0c43987cf205', 'e831f61c-34c5-4c34-a817-d6f97f0a2184'),
('227c2638-b71f-497a-bb8e-a3bf75adfe62', 'Aaron', 'Sanders', 'mcdonaldsteve@testsite.org', 'scrypt:32768:8:1$ZvDeB1hRHqNZuYHD$9a22c9a790319f357307033d69b9ef637d6e86195c76dc798a7c6f242850f78dbd1a1771640817f7e944c4067f3a5a79b6183547ca28e3215ff095462c4d528a', 'profile_68.jpg', 1733007675, 0, 0, 0, 0, '1b5e2a4e-3baa-4928-a321-8941e3271a67', ''),
('295d996f-b718-4b17-bc30-475fb5894274', 'Cynthia', 'Smith', 'wesleybooth@example.net', 'scrypt:32768:8:1$NkzOQ4pEodHCC85q$dac9775af7d9391ad611b0f25b109eba1a98ec1f0441a0424d3e8b6211b5ab0cd53542c9b8d405735b85e656f54241c6d6e689b2a28c58978f8a2adb94b04a9c', 'profile_1.jpg', 1733007675, 0, 0, 0, 1733007675, 'c352f33d-db2e-4728-aebe-4cedebda3fa8', ''),
('305b04e6-41c5-4826-8188-6380f70ab1c6', 'Ebony', '', 'tanya78@example.net', 'scrypt:32768:8:1$ZH853zn95F6Eu189$9d00a9af581c5f0a46d229d6eb8eda889d25c74278e51125e9805c975d815c621925cecfef6fa4c94788f02a7a445f8d767ee0e213f0ecfa44b549fbb952bda6', 'profile_47.jpg', 1733007675, 0, 0, 1733086114, 1733007675, 'b822dea5-3c3a-43a6-842f-41b221f28b76', ''),
('36953562-1e04-4047-8e1d-6d2d390957b7', 'Adriana', 'Pierce', 'jacquelineshah@example.org', 'scrypt:32768:8:1$NkzOQ4pEodHCC85q$dac9775af7d9391ad611b0f25b109eba1a98ec1f0441a0424d3e8b6211b5ab0cd53542c9b8d405735b85e656f54241c6d6e689b2a28c58978f8a2adb94b04a9c', 'profile_39.jpg', 1733007675, 0, 0, 0, 1733007675, 'a3c492aa-0745-45a4-8ebf-8b90fedeca75', ''),
('3883a969-4d60-4bf3-9343-26bbb0fd0008', 'Julie', 'Grønborg', 'jj@hotmail.com', 'scrypt:32768:8:1$zU0CqbzrkYN45yXe$771809ee0a4efc3250fe2f99c1bbea137614d225f66f32540f9a0aea720369d8396e202824038fe7b897a4f0e3f3725aff361d8132ccf7f3080aa481e2b2b105', '', 1733060694, 0, 0, 0, 0, 'd9e93a10-e8c5-4104-ab25-fba7e68fedf5', '0'),
('4218788d-03b7-4812-bd7d-31c8859e92d8', 'John', 'Customer', 'customer@fulldemo.com', 'scrypt:32768:8:1$ubfCU2RaiXsgzMJQ$5501c293720b35a6c37e69c3e83a2ba6c942e7b69856417c31317d1a8d06de0a7df69140208fd56681dbfea41dbfb45c5bc7f37c880a8648d009763ae89a4924', 'profile_11.jpg', 1733007675, 0, 0, 0, 1733007675, '7a8f0ba7-730e-4508-b48e-9b6415ce681b', ''),
('449f41b1-6d24-4358-ab2f-08ccf5956fef', 'Aaron', 'Harrison', 'markevans@website.co', 'scrypt:32768:8:1$ZvDeB1hRHqNZuYHD$9a22c9a790319f357307033d69b9ef637d6e86195c76dc798a7c6f242850f78dbd1a1771640817f7e944c4067f3a5a79b6183547ca28e3215ff095462c4d528a', 'profile_31.jpg', 1733007675, 0, 0, 0, 1733007675, '4dba5924-7d56-49f5-9c82-94812a9127bb', ''),
('44c2aef6-1797-461e-be27-649f2b03508a', 'Stephen', 'Gutierrez', 'brandon16@example.com', 'scrypt:32768:8:1$NkzOQ4pEodHCC85q$dac9775af7d9391ad611b0f25b109eba1a98ec1f0441a0424d3e8b6211b5ab0cd53542c9b8d405735b85e656f54241c6d6e689b2a28c58978f8a2adb94b04a9c', 'profile_38.jpg', 1733007675, 0, 0, 0, 0, '97187abf-8a41-4113-b17a-273860cb889c', ''),
('49966367-0a9e-49e3-a5b4-15800f56ed2e', 'Joshua', '', 'chase26@example.org', 'scrypt:32768:8:1$ZH853zn95F6Eu189$9d00a9af581c5f0a46d229d6eb8eda889d25c74278e51125e9805c975d815c621925cecfef6fa4c94788f02a7a445f8d767ee0e213f0ecfa44b549fbb952bda6', 'profile_95.jpg', 1733007675, 0, 0, 0, 0, '438f226f-25ef-4921-8897-73fc84b6eabc', ''),
('5213ea63-5893-48d8-81e0-9886b7f7769a', 'Karla', '', 'edwinschmidt@example.com', 'scrypt:32768:8:1$ZH853zn95F6Eu189$9d00a9af581c5f0a46d229d6eb8eda889d25c74278e51125e9805c975d815c621925cecfef6fa4c94788f02a7a445f8d767ee0e213f0ecfa44b549fbb952bda6', 'profile_44.jpg', 1733007675, 0, 0, 0, 0, '3caf81a9-deb9-4c89-bb87-b8c1ba403d21', ''),
('582454e7-3b7b-445c-bff1-08fe42956c5a', 'Kiki', '', 'kiki@hotmail.com', 'scrypt:32768:8:1$7kqXZ1yRBb7wdykt$bc1ab502d365e74e8f236d1a712b23b9df976f90c4281cc570e5e9a556dd69de66f196123cf82a95301ea84fc03983e23b611298d2f44dd3d46d900a67fe69cf', '', 1733059253, 0, 0, 0, 0, 'd48e37df-6fd9-44a9-8741-d439836222fe', '0'),
('5d2c1505-0439-46de-a8af-b0f7813d0b1f', 'Melissa', 'Bell', 'janetdiaz@mydomain.net', 'scrypt:32768:8:1$ZvDeB1hRHqNZuYHD$9a22c9a790319f357307033d69b9ef637d6e86195c76dc798a7c6f242850f78dbd1a1771640817f7e944c4067f3a5a79b6183547ca28e3215ff095462c4d528a', 'profile_14.jpg', 1733007675, 0, 0, 0, 1733007675, '7eaa202d-1de5-4ef3-a3c9-0676e3f2441e', ''),
('695e32c5-0fa2-44f3-985a-80a6c7a62883', 'Kelly', '', 'farmerjonathan@example.net', 'scrypt:32768:8:1$ZH853zn95F6Eu189$9d00a9af581c5f0a46d229d6eb8eda889d25c74278e51125e9805c975d815c621925cecfef6fa4c94788f02a7a445f8d767ee0e213f0ecfa44b549fbb952bda6', 'profile_86.jpg', 1733007675, 0, 0, 0, 0, 'fa60690e-15cf-420b-8aa1-8949f4ad0f75', ''),
('9393d210-aee5-4bb4-99af-33c9cdf2839a', 'Erin', 'Morales', 'fthomas@example.com', 'scrypt:32768:8:1$NkzOQ4pEodHCC85q$dac9775af7d9391ad611b0f25b109eba1a98ec1f0441a0424d3e8b6211b5ab0cd53542c9b8d405735b85e656f54241c6d6e689b2a28c58978f8a2adb94b04a9c', 'profile_28.jpg', 1733007675, 0, 0, 0, 1733007675, '8153a5e0-5207-4c93-b38c-e32288a2a737', ''),
('9fd04253-a143-48bb-aa9d-3f371638aa91', 'Koko', 'Koko', 'ko@hotmail.com', 'scrypt:32768:8:1$C3xLDdYwJWqEHs1k$b9b16d17bc1512e711439d3de8bc29c882d15579f93f3f94b70478854fa0eb22d87b49e8439218c726e43167f5dd023db54ee80d80f19025e556e86c56bb857a', '', 1733054361, 0, 0, 0, 0, 'e78b6ef8-a78f-4c74-89a9-c2cf9f2e2c13', '0'),
('a2f4f5fd-d3cb-46d6-b5d7-28a2742d068c', 'Tiffany', 'Martin', 'joshua23@example.net', 'scrypt:32768:8:1$NkzOQ4pEodHCC85q$dac9775af7d9391ad611b0f25b109eba1a98ec1f0441a0424d3e8b6211b5ab0cd53542c9b8d405735b85e656f54241c6d6e689b2a28c58978f8a2adb94b04a9c', 'profile_35.jpg', 1733007675, 0, 1733086104, 1733086104, 1733007675, '2138b186-6d12-4bf0-a5a5-883fd5fc9f5f', ''),
('a6ca214e-d3c5-4a85-a948-d2bdb0becfaa', 'Timothy', '', 'vsantiago@example.com', 'scrypt:32768:8:1$ZH853zn95F6Eu189$9d00a9af581c5f0a46d229d6eb8eda889d25c74278e51125e9805c975d815c621925cecfef6fa4c94788f02a7a445f8d767ee0e213f0ecfa44b549fbb952bda6', 'profile_83.jpg', 1733007675, 0, 0, 0, 1733007675, 'd477c3d1-a1c2-4200-ab8c-4b00b95356f8', ''),
('b30fdc89-91b0-49fb-9794-11e01a4ae24b', 'Stacy', 'Bailey', 'angelawilson@hotmail.com', 'scrypt:32768:8:1$ZvDeB1hRHqNZuYHD$9a22c9a790319f357307033d69b9ef637d6e86195c76dc798a7c6f242850f78dbd1a1771640817f7e944c4067f3a5a79b6183547ca28e3215ff095462c4d528a', 'profile_68.jpg', 1733007675, 0, 1733049515, 1733049515, 1733007675, 'e550ea1d-f0db-4938-b894-cbf31eda7a01', ''),
('b3991867-310f-437b-a5ab-177c33be8c46', 'Lisa', '', 'mrodriguez@example.org', 'scrypt:32768:8:1$ZH853zn95F6Eu189$9d00a9af581c5f0a46d229d6eb8eda889d25c74278e51125e9805c975d815c621925cecfef6fa4c94788f02a7a445f8d767ee0e213f0ecfa44b549fbb952bda6', 'profile_60.jpg', 1733007675, 0, 0, 0, 1733007675, '83a0d73f-5a9f-496b-867d-e0adc44b4c1a', ''),
('b67e321e-048f-46c3-9d8b-c78a851a5cba', 'kokok', 'okokok', 'okokok@hotmail.com', 'scrypt:32768:8:1$hUWCsvjXMEKJ47em$52e2898a13ca82af8136eb07b50a58d6dba72557c754f8f175f1ca69ace53b3b2d908417a529d6fa05bd1c4bf8a4162a7a31be6cdbd32621489a53db3cf50a20', '', 1733059165, 0, 0, 0, 0, '6f446c7a-5726-47a9-a5f6-a0775b81e7c6', '0'),
('bf9e7352-6a44-4e03-abc2-52f7558bf071', 'John', 'Partner', 'partner@fulldemo.com', 'scrypt:32768:8:1$66Ac5wQQpNny026Y$b11875b7197aaf2b7287c01e05f47ea731c6038b23cd63871d9764821cf974216a14d5e5919b36faaabf347020c8699bd4427bfe8c59a3581f83bd0e6a04ee14', 'profile_12.jpg', 1733007675, 0, 1733046042, 0, 1733007675, '49fb351c-51fb-4cf1-bc49-47410f38852b', ''),
('c8061145-2ff0-4174-bd73-3261946400e4', 'Santiago', 'Donoso', 'admin@fulldemo.com', 'scrypt:32768:8:1$6khGsjoa1TJKm1pH$a80c356eb7c4a91608137067509809f674fc94e66864aaebdacec52c0b2eaf14b53654e4a403362b283d791191320e15c0bac4d55fd35c998f35d38d2fac5247', 'profile_10.jpg', 1733007674, 0, 0, 1733077949, 2, '74409837-aa53-4e3c-b177-8b8f602b961c', '0'),
('ca405c31-13a7-4fc5-a541-4a160bc4f5cb', 'Lori', 'Williams', 'zpena@example.com', 'scrypt:32768:8:1$NkzOQ4pEodHCC85q$dac9775af7d9391ad611b0f25b109eba1a98ec1f0441a0424d3e8b6211b5ab0cd53542c9b8d405735b85e656f54241c6d6e689b2a28c58978f8a2adb94b04a9c', 'profile_50.jpg', 1733007675, 0, 0, 0, 0, '637af6c0-bd5b-45c3-9678-bcbdd2fa0322', ''),
('cc01814c-1625-4d35-ac61-e6c7f1600c2b', 'Richard', 'Owens', 'amyflores@example.org', 'scrypt:32768:8:1$NkzOQ4pEodHCC85q$dac9775af7d9391ad611b0f25b109eba1a98ec1f0441a0424d3e8b6211b5ab0cd53542c9b8d405735b85e656f54241c6d6e689b2a28c58978f8a2adb94b04a9c', 'profile_87.jpg', 1733007675, 0, 0, 0, 0, '9fd0ea2c-7f27-40f9-adab-9fa7a9907308', ''),
('cd6b7f6b-7dad-45e6-a47b-2e2e4877eaa0', 'Jennifer', 'Cooke', 'mshepard@hotmail.com', 'scrypt:32768:8:1$ZvDeB1hRHqNZuYHD$9a22c9a790319f357307033d69b9ef637d6e86195c76dc798a7c6f242850f78dbd1a1771640817f7e944c4067f3a5a79b6183547ca28e3215ff095462c4d528a', 'profile_70.jpg', 1733007675, 0, 0, 0, 0, 'a62be265-3f9e-483e-81cc-1a6f2813e5c8', ''),
('ceb88a4b-4ced-4292-8b98-ed25e7156c43', 'Anthony', 'Mccormick', 'kennethevans@mydomain.net', 'scrypt:32768:8:1$ZvDeB1hRHqNZuYHD$9a22c9a790319f357307033d69b9ef637d6e86195c76dc798a7c6f242850f78dbd1a1771640817f7e944c4067f3a5a79b6183547ca28e3215ff095462c4d528a', 'profile_13.jpg', 1733007675, 0, 1733046152, 0, 1733007675, '05d02ac3-bd1c-476a-85f6-3a1adeb140cd', ''),
('d11164ce-710a-4e6c-bd01-6c7857656000', 'Kimberly', 'Humphrey', 'william03@testsite.org', 'scrypt:32768:8:1$ZvDeB1hRHqNZuYHD$9a22c9a790319f357307033d69b9ef637d6e86195c76dc798a7c6f242850f78dbd1a1771640817f7e944c4067f3a5a79b6183547ca28e3215ff095462c4d528a', 'profile_39.jpg', 1733007675, 0, 0, 0, 0, '62172394-6fca-404d-bc62-e6db2059ce3a', ''),
('d47a9b21-831a-4663-80b6-310aee943333', 'Christopher', 'Gallegos', 'kathleen65@example.org', 'scrypt:32768:8:1$NkzOQ4pEodHCC85q$dac9775af7d9391ad611b0f25b109eba1a98ec1f0441a0424d3e8b6211b5ab0cd53542c9b8d405735b85e656f54241c6d6e689b2a28c58978f8a2adb94b04a9c', 'profile_27.jpg', 1733007675, 0, 0, 0, 0, '9dca401c-7330-4a2e-abea-a95293506709', ''),
('df565aee-35a0-4d9c-bb05-a44b1aa2f7c1', 'Jacob', 'Simmons', 'sandrawiggins@testsite.org', 'scrypt:32768:8:1$ZvDeB1hRHqNZuYHD$9a22c9a790319f357307033d69b9ef637d6e86195c76dc798a7c6f242850f78dbd1a1771640817f7e944c4067f3a5a79b6183547ca28e3215ff095462c4d528a', 'profile_76.jpg', 1733007675, 0, 0, 0, 0, 'b1392474-3e0f-4101-8d39-04366c9e6565', ''),
('e723abbd-68e7-4120-9aef-348f07f84a10', 'Bradley', 'Wolf', 'kathrynmiller@gmail.com', 'scrypt:32768:8:1$ZvDeB1hRHqNZuYHD$9a22c9a790319f357307033d69b9ef637d6e86195c76dc798a7c6f242850f78dbd1a1771640817f7e944c4067f3a5a79b6183547ca28e3215ff095462c4d528a', 'profile_25.jpg', 1733007675, 0, 0, 0, 1733007675, 'b6a5dd10-bd39-4983-abde-7776ae96cb1a', ''),
('f4edfe88-1331-46d3-8099-cf92bcb662d5', 'Alan', 'Welch', 'barretttyler@example.com', 'scrypt:32768:8:1$NkzOQ4pEodHCC85q$dac9775af7d9391ad611b0f25b109eba1a98ec1f0441a0424d3e8b6211b5ab0cd53542c9b8d405735b85e656f54241c6d6e689b2a28c58978f8a2adb94b04a9c', 'profile_57.jpg', 1733007675, 0, 0, 0, 0, '1629eabf-a6f5-4a8b-bfbe-9241e42199d1', ''),
('fb2f4334-fd7a-4089-adc1-37d099bf46d5', 'Eric', '', 'gkeith@example.org', 'scrypt:32768:8:1$ZH853zn95F6Eu189$9d00a9af581c5f0a46d229d6eb8eda889d25c74278e51125e9805c975d815c621925cecfef6fa4c94788f02a7a445f8d767ee0e213f0ecfa44b549fbb952bda6', 'profile_64.jpg', 1733007675, 0, 0, 0, 1733007675, 'ba25a976-e0db-48f9-8474-daffd7dfdc80', ''),
('fd64c6a1-5d33-4e69-8371-304004e5c349', 'Robert', '', 'kristina73@example.org', 'scrypt:32768:8:1$ZH853zn95F6Eu189$9d00a9af581c5f0a46d229d6eb8eda889d25c74278e51125e9805c975d815c621925cecfef6fa4c94788f02a7a445f8d767ee0e213f0ecfa44b549fbb952bda6', 'profile_54.jpg', 1733007675, 0, 0, 0, 1733007675, '30c272d7-beab-41b8-a623-aa7de41e3e21', ''),
('ffb6c6e5-e249-46a7-9391-314ecf9c8cf6', 'Edwin', 'Colon', 'smithjoseph@example.net', 'scrypt:32768:8:1$NkzOQ4pEodHCC85q$dac9775af7d9391ad611b0f25b109eba1a98ec1f0441a0424d3e8b6211b5ab0cd53542c9b8d405735b85e656f54241c6d6e689b2a28c58978f8a2adb94b04a9c', 'profile_73.jpg', 1733007675, 0, 0, 0, 0, 'c33dbc43-592c-43aa-ba5c-490a5ed533e5', '');

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
('c8061145-2ff0-4174-bd73-3261946400e4', '16fd2706-8baf-433b-82eb-8c7fada847da'),
('14cb5887-f539-42be-8f0d-06485866232b', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('17394923-34ac-4eb3-bd71-6837f308b15e', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('1f0f49ec-0d7e-4274-a697-e4c2f6aaa64e', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('305b04e6-41c5-4826-8188-6380f70ab1c6', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('49966367-0a9e-49e3-a5b4-15800f56ed2e', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('5213ea63-5893-48d8-81e0-9886b7f7769a', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('582454e7-3b7b-445c-bff1-08fe42956c5a', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('695e32c5-0fa2-44f3-985a-80a6c7a62883', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('a6ca214e-d3c5-4a85-a948-d2bdb0becfaa', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('b3991867-310f-437b-a5ab-177c33be8c46', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('fb2f4334-fd7a-4089-adc1-37d099bf46d5', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('fd64c6a1-5d33-4e69-8371-304004e5c349', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('1df25c60-06d7-4ea1-89db-eec833cbe518', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('227c2638-b71f-497a-bb8e-a3bf75adfe62', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('3883a969-4d60-4bf3-9343-26bbb0fd0008', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('4218788d-03b7-4812-bd7d-31c8859e92d8', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('449f41b1-6d24-4358-ab2f-08ccf5956fef', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('5d2c1505-0439-46de-a8af-b0f7813d0b1f', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('9fd04253-a143-48bb-aa9d-3f371638aa91', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('b30fdc89-91b0-49fb-9794-11e01a4ae24b', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('b67e321e-048f-46c3-9d8b-c78a851a5cba', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('cd6b7f6b-7dad-45e6-a47b-2e2e4877eaa0', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('ceb88a4b-4ced-4292-8b98-ed25e7156c43', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('d11164ce-710a-4e6c-bd01-6c7857656000', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('df565aee-35a0-4d9c-bb05-a44b1aa2f7c1', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('e723abbd-68e7-4120-9aef-348f07f84a10', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('295d996f-b718-4b17-bc30-475fb5894274', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('36953562-1e04-4047-8e1d-6d2d390957b7', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('44c2aef6-1797-461e-be27-649f2b03508a', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('9393d210-aee5-4bb4-99af-33c9cdf2839a', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('a2f4f5fd-d3cb-46d6-b5d7-28a2742d068c', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('bf9e7352-6a44-4e03-abc2-52f7558bf071', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('ca405c31-13a7-4fc5-a541-4a160bc4f5cb', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('cc01814c-1625-4d35-ac61-e6c7f1600c2b', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('d47a9b21-831a-4663-80b6-310aee943333', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('f4edfe88-1331-46d3-8099-cf92bcb662d5', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('ffb6c6e5-e249-46a7-9391-314ecf9c8cf6', 'f47ac10b-58cc-4372-a567-0e02b2c3d479');

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
