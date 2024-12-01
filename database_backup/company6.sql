-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Vært: mysql
-- Genereringstid: 29. 11 2024 kl. 16:56:48
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
('0920f1ff-71ad-4081-9890-72ece4adff76', 'e8a62b62-bdba-4222-9aa4-28c64b24c52f', 'Chicken Alfredo', 608.90, 'dish_67.jpg', 'dish_67.jpg', 'dish_67.jpg', 1732898999, 0, 0, 0),
('0faa90d2-50fd-4264-bba2-ec8adaa358fa', '2b6bf046-40ef-4f1d-adf3-07b7bd6e1a5d', 'Fish and Chips', 912.11, 'dish_45.jpg', 'dish_45.jpg', 'dish_45.jpg', 1732898999, 0, 0, 0),
('161c8a02-e224-471f-8a4f-52c1817e0b91', '2b757ede-a315-4a3a-b637-c58969936269', 'Pizza Margherita', 647.53, 'dish_30.jpg', 'dish_30.jpg', 'dish_30.jpg', 1732898999, 0, 0, 0),
('1f83ebe1-b9be-42cf-a0ab-aa6894f1b47c', '6cb7edb3-a661-4bf5-88b5-332059834722', 'Frittata', 802.54, 'dish_19.jpg', 'dish_19.jpg', 'dish_19.jpg', 1732898999, 0, 0, 0),
('21f45d89-4f53-409f-9aab-5d4ab3ea139f', '380b1aec-1d42-472e-8d07-32d406291394', 'Peking Duck', 556.08, 'dish_78.jpg', 'dish_78.jpg', 'dish_78.jpg', 1732898999, 0, 0, 0),
('2394dbfb-9b45-47ef-9ae4-186c0e6e8a04', '71fdb80a-e6c1-487e-852c-df99edbd9934', 'Empanadas de Pollo', 695.50, 'dish_84.jpg', 'dish_84.jpg', 'dish_84.jpg', 1732898999, 0, 0, 0),
('35502500-8387-451f-bd5f-25b98307e0cc', '38294873-0bff-444f-b1d9-b6a3e4fcd481', 'Spaghetti Carbonara', 545.02, 'dish_49.jpg', 'dish_49.jpg', 'dish_49.jpg', 1732898999, 0, 0, 0),
('38ec212e-b92d-4091-b9e9-250105a40b78', '2b757ede-a315-4a3a-b637-c58969936269', 'Hummus', 981.82, 'dish_92.jpg', 'dish_92.jpg', 'dish_92.jpg', 1732898999, 0, 0, 0),
('3ea233a2-d411-44ba-abee-f82358bfa077', '71fdb80a-e6c1-487e-852c-df99edbd9934', 'Enchiladas', 746.54, 'dish_68.jpg', 'dish_68.jpg', 'dish_68.jpg', 1732898999, 0, 0, 0),
('408a7839-bc9e-4389-a561-b931388fca3e', '2b757ede-a315-4a3a-b637-c58969936269', 'Chicken Alfredo', 559.91, 'dish_21.jpg', 'dish_21.jpg', 'dish_21.jpg', 1732898999, 0, 0, 0),
('45c860c3-1756-4ec2-91db-50cb4527218a', '380b1aec-1d42-472e-8d07-32d406291394', 'Shawarma', 547.61, 'dish_6.jpg', 'dish_6.jpg', 'dish_6.jpg', 1732898999, 0, 0, 0),
('45e9e9b7-8adb-4542-ba62-0a6f115ccbbc', '71fdb80a-e6c1-487e-852c-df99edbd9934', 'Chicken Alfredo', 706.58, 'dish_97.jpg', 'dish_97.jpg', 'dish_97.jpg', 1732898999, 0, 0, 0),
('486da947-4c4c-4ca8-ace9-08841099e666', 'e8a62b62-bdba-4222-9aa4-28c64b24c52f', 'Biryani', 902.48, 'dish_6.jpg', 'dish_6.jpg', 'dish_6.jpg', 1732898999, 0, 0, 0),
('49373609-ba70-4bdc-ab94-142360a30406', '380b1aec-1d42-472e-8d07-32d406291394', 'Burrito', 807.25, 'dish_92.jpg', 'dish_92.jpg', 'dish_92.jpg', 1732898999, 0, 0, 0),
('4a98ab11-55f3-4a9b-b9f1-a5e2a181588e', '71fdb80a-e6c1-487e-852c-df99edbd9934', 'Moussaka', 678.24, 'dish_59.jpg', 'dish_59.jpg', 'dish_59.jpg', 1732898999, 0, 0, 0),
('512288e9-60d5-424f-b6ee-e9159fbf0e56', '13a6a7ea-3f71-4a09-98d2-a795a31e25d0', 'Bangers and Mash', 684.04, 'dish_73.jpg', 'dish_73.jpg', 'dish_73.jpg', 1732898999, 0, 0, 0),
('5160ba9b-b9d7-46b6-9182-a57e53f94f03', '2b6bf046-40ef-4f1d-adf3-07b7bd6e1a5d', 'Clafoutis', 881.62, 'dish_69.jpg', 'dish_69.jpg', 'dish_69.jpg', 1732898999, 0, 0, 0),
('53004ba2-c6f7-4d8f-a38e-cec97b2a489f', '2b757ede-a315-4a3a-b637-c58969936269', 'Mole Poblano', 817.97, 'dish_79.jpg', 'dish_79.jpg', 'dish_79.jpg', 1732898999, 0, 0, 0),
('53878c47-763c-4753-b6e3-eaaa98142b01', '71fdb80a-e6c1-487e-852c-df99edbd9934', 'Nasi Goreng', 940.17, 'dish_64.jpg', 'dish_64.jpg', 'dish_64.jpg', 1732898999, 0, 0, 0),
('552d8f4e-ff09-41b3-821d-b8ef64e47e35', '184990c6-2b42-4ce0-a185-887f7c3afd28', 'Fish and Chips', 996.18, 'dish_40.jpg', 'dish_40.jpg', 'dish_40.jpg', 1732898999, 0, 0, 0),
('5af69522-d941-40a0-8b88-558c235bb959', '38294873-0bff-444f-b1d9-b6a3e4fcd481', 'Crepes', 682.59, 'dish_35.jpg', 'dish_35.jpg', 'dish_35.jpg', 1732898999, 0, 0, 0),
('5bb7d12e-58f3-4eae-8cb9-4acc9e21a301', '13a6a7ea-3f71-4a09-98d2-a795a31e25d0', 'Tofu Scramble', 658.46, 'dish_98.jpg', 'dish_98.jpg', 'dish_98.jpg', 1732898999, 0, 0, 0),
('62a2b2bf-033d-49cd-80fa-e540486076c1', '2b6bf046-40ef-4f1d-adf3-07b7bd6e1a5d', 'Hot Pot', 991.58, 'dish_9.jpg', 'dish_9.jpg', 'dish_9.jpg', 1732898999, 0, 0, 0),
('6c32e7c6-9b95-46e2-aa70-d30c7e8df503', '13a6a7ea-3f71-4a09-98d2-a795a31e25d0', 'Bulgogi', 806.27, 'dish_82.jpg', 'dish_82.jpg', 'dish_82.jpg', 1732898999, 0, 0, 0),
('6c41e072-dd86-4cee-bd7f-c2aacb3016f1', '2b757ede-a315-4a3a-b637-c58969936269', 'Falafel', 946.41, 'dish_11.jpg', 'dish_11.jpg', 'dish_11.jpg', 1732898999, 0, 0, 0),
('6e6e9c2c-c42a-4e15-8506-3f1678d4b00c', '2b6bf046-40ef-4f1d-adf3-07b7bd6e1a5d', 'Schnitzel', 853.50, 'dish_58.jpg', 'dish_58.jpg', 'dish_58.jpg', 1732898999, 0, 0, 0),
('70e228e2-f37d-4dc6-a877-383b1b71024f', '6cb7edb3-a661-4bf5-88b5-332059834722', 'Shrimp Scampi', 676.65, 'dish_44.jpg', 'dish_44.jpg', 'dish_44.jpg', 1732898999, 0, 0, 0),
('73740846-ace8-429e-9ecb-608862ca0145', '6cb7edb3-a661-4bf5-88b5-332059834722', 'Mango Sticky Rice', 564.98, 'dish_34.jpg', 'dish_34.jpg', 'dish_34.jpg', 1732898999, 0, 0, 0),
('7dd7af78-4e29-441a-ad53-72a14f70d8d0', '2b6bf046-40ef-4f1d-adf3-07b7bd6e1a5d', 'Souvlaki', 733.34, 'dish_12.jpg', 'dish_12.jpg', 'dish_12.jpg', 1732898999, 0, 0, 0),
('81b01b3f-9821-49c4-aa85-a59783a090e6', '27547afd-1941-4308-a6c9-f2d6c53b753a', 'Chili Con Carne', 662.59, 'dish_47.jpg', 'dish_47.jpg', 'dish_47.jpg', 1732898999, 0, 0, 0),
('863e50cc-db5e-4dec-8622-d0b27ef0abe9', '380b1aec-1d42-472e-8d07-32d406291394', 'Quiche', 560.50, 'dish_67.jpg', 'dish_67.jpg', 'dish_67.jpg', 1732898999, 0, 0, 0),
('9597bd61-3b1c-4353-b9e9-dcdf89ac9e93', '38294873-0bff-444f-b1d9-b6a3e4fcd481', 'Chateaubriand', 625.52, 'dish_60.jpg', 'dish_60.jpg', 'dish_60.jpg', 1732898999, 0, 0, 0),
('96755f07-9e83-470a-8bf7-6aecc29d46ae', 'e8a62b62-bdba-4222-9aa4-28c64b24c52f', 'Burrito', 502.16, 'dish_45.jpg', 'dish_45.jpg', 'dish_45.jpg', 1732898999, 0, 0, 0),
('a06de2d3-c137-48f2-a6a4-4b40eec7068f', '27547afd-1941-4308-a6c9-f2d6c53b753a', 'Lamb Tagine', 612.03, 'dish_50.jpg', 'dish_50.jpg', 'dish_50.jpg', 1732898999, 0, 0, 0),
('a2d652ba-7d5b-4aad-8719-80ebb92a1337', '38294873-0bff-444f-b1d9-b6a3e4fcd481', 'Tandoori Chicken', 576.06, 'dish_99.jpg', 'dish_99.jpg', 'dish_99.jpg', 1732898999, 0, 0, 0),
('a7dfccf1-a128-43bf-a131-9ddea1217844', '38294873-0bff-444f-b1d9-b6a3e4fcd481', 'Paella', 907.58, 'dish_87.jpg', 'dish_87.jpg', 'dish_87.jpg', 1732898999, 0, 0, 0),
('ac0d5b80-ea25-4e75-ba3e-a62e0acd8a59', '38294873-0bff-444f-b1d9-b6a3e4fcd481', 'Sushi', 904.52, 'dish_92.jpg', 'dish_92.jpg', 'dish_92.jpg', 1732898999, 0, 0, 0),
('b3024383-91c3-413e-af70-213443c3350c', '184990c6-2b42-4ce0-a185-887f7c3afd28', 'Bangers and Mash', 989.90, 'dish_10.jpg', 'dish_10.jpg', 'dish_10.jpg', 1732898999, 0, 0, 0),
('b9ce4bd1-1e11-4a58-9eb5-596bb48e4377', '13a6a7ea-3f71-4a09-98d2-a795a31e25d0', 'Beef Stroganoff', 808.86, 'dish_34.jpg', 'dish_34.jpg', 'dish_34.jpg', 1732898999, 0, 0, 0),
('bbc52842-4547-4745-af66-37787224ab84', '27547afd-1941-4308-a6c9-f2d6c53b753a', 'Tortilla Española', 545.42, 'dish_11.jpg', 'dish_11.jpg', 'dish_11.jpg', 1732898999, 0, 0, 0),
('c27fbb71-c853-4d94-a4d9-84014a70184c', 'e8a62b62-bdba-4222-9aa4-28c64b24c52f', 'Masala Dosa', 877.65, 'dish_41.jpg', 'dish_41.jpg', 'dish_41.jpg', 1732898999, 0, 0, 0),
('c4a4266c-a503-4aea-b0fa-bdef1bb9f956', '27547afd-1941-4308-a6c9-f2d6c53b753a', 'Sweet and Sour Pork', 894.87, 'dish_12.jpg', 'dish_12.jpg', 'dish_12.jpg', 1732898999, 0, 0, 0),
('c5fcdc15-6e6f-48de-b7e1-38c2097ac987', '6cb7edb3-a661-4bf5-88b5-332059834722', 'Nasi Goreng', 824.07, 'dish_59.jpg', 'dish_59.jpg', 'dish_59.jpg', 1732898999, 0, 0, 0),
('cb800c50-d6d4-4e0c-99c2-9d86dd128b6b', 'e8a62b62-bdba-4222-9aa4-28c64b24c52f', 'Dim Sum', 696.09, 'dish_99.jpg', 'dish_99.jpg', 'dish_99.jpg', 1732898999, 0, 0, 0),
('ceab3af0-733e-47c0-a46e-7038cfa4338d', '184990c6-2b42-4ce0-a185-887f7c3afd28', 'Paella', 729.24, 'dish_76.jpg', 'dish_76.jpg', 'dish_76.jpg', 1732898999, 0, 0, 0),
('cfc2c599-e905-4407-86d0-a52512a3a2dd', '2b757ede-a315-4a3a-b637-c58969936269', 'Baked Ziti', 774.05, 'dish_100.jpg', 'dish_100.jpg', 'dish_100.jpg', 1732898999, 0, 0, 0),
('d3ca2e4e-ee30-4097-84dd-9668bc037957', '13a6a7ea-3f71-4a09-98d2-a795a31e25d0', 'Meatloaf', 756.14, 'dish_11.jpg', 'dish_11.jpg', 'dish_11.jpg', 1732898999, 0, 0, 0),
('d424abdc-8900-41c1-8213-d9bf9de98905', '6cb7edb3-a661-4bf5-88b5-332059834722', 'Dim Sum', 791.54, 'dish_30.jpg', 'dish_30.jpg', 'dish_30.jpg', 1732898999, 0, 0, 0),
('d57760b7-4747-4b9e-86d1-719125fe5981', 'e8a62b62-bdba-4222-9aa4-28c64b24c52f', 'Moussaka', 608.81, 'dish_61.jpg', 'dish_61.jpg', 'dish_61.jpg', 1732898999, 0, 0, 0),
('e0ffd133-4926-4a6b-bde8-7c0f7bfab73e', '184990c6-2b42-4ce0-a185-887f7c3afd28', 'Pho', 775.63, 'dish_40.jpg', 'dish_40.jpg', 'dish_40.jpg', 1732898999, 0, 0, 0),
('e4f3d739-dd29-4a21-bc9c-10599de8185a', '184990c6-2b42-4ce0-a185-887f7c3afd28', 'Ahi Poke', 641.71, 'dish_18.jpg', 'dish_18.jpg', 'dish_18.jpg', 1732898999, 0, 0, 0),
('e8e81d26-28c9-4916-a246-c869b2947ae6', '27547afd-1941-4308-a6c9-f2d6c53b753a', 'Roti', 529.32, 'dish_88.jpg', 'dish_88.jpg', 'dish_88.jpg', 1732898999, 0, 0, 0),
('e9631b64-00c9-4ca6-a5d2-5a6958de1056', '27547afd-1941-4308-a6c9-f2d6c53b753a', 'Chicken Shawarma', 729.41, 'dish_12.jpg', 'dish_12.jpg', 'dish_12.jpg', 1732898999, 0, 0, 0),
('eb74716e-2ac3-4fcc-b381-17398cbd94ba', '380b1aec-1d42-472e-8d07-32d406291394', 'Yakitori', 869.84, 'dish_12.jpg', 'dish_12.jpg', 'dish_12.jpg', 1732898999, 0, 0, 0),
('ef0d27dc-4289-4720-94e3-96b6cf65c7a3', '71fdb80a-e6c1-487e-852c-df99edbd9934', 'Bangers and Mash', 783.25, 'dish_74.jpg', 'dish_74.jpg', 'dish_74.jpg', 1732898999, 0, 0, 0),
('efe18d68-6dcc-45f5-9e3f-57d311c03946', '380b1aec-1d42-472e-8d07-32d406291394', 'Croissant', 883.47, 'dish_52.jpg', 'dish_52.jpg', 'dish_52.jpg', 1732898999, 0, 0, 0),
('f5899afd-679f-49d4-a001-4b55994eb786', '2b6bf046-40ef-4f1d-adf3-07b7bd6e1a5d', 'Yakitori', 813.87, 'dish_62.jpg', 'dish_62.jpg', 'dish_62.jpg', 1732898999, 0, 0, 0),
('f898fa37-9548-4146-a87f-9d4035a02b2e', '6cb7edb3-a661-4bf5-88b5-332059834722', 'Ahi Poke', 689.03, 'dish_46.jpg', 'dish_46.jpg', 'dish_46.jpg', 1732898999, 0, 0, 0),
('fc3895ba-0cac-43c4-9e3c-a487a15b0817', '13a6a7ea-3f71-4a09-98d2-a795a31e25d0', 'Paella', 509.70, 'dish_56.jpg', 'dish_56.jpg', 'dish_56.jpg', 1732898999, 0, 0, 0),
('fe6855db-4c6d-4d79-bcf3-9059a8a79d12', '184990c6-2b42-4ce0-a185-887f7c3afd28', 'Paella Valenciana', 550.64, 'dish_16.jpg', 'dish_16.jpg', 'dish_16.jpg', 1732898999, 0, 0, 0);

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
('03c8a049-51e1-4f2c-b42b-eca43bccd50b', 'Peggy', 'Lopez', 'fallen@fakemail.io', 'scrypt:32768:8:1$RVtKgS91KREyUvJD$7d443b51c3638e8c36e32fe3a6bd35cce7bcddacd01ce1fd63e61531de51275e3c61ce97f1ad23744660ff61885b3f7c8d2f24af6e65208174b0d4b021b2fdbc', 'profile_35.jpg', 1732898999, 0, 0, 0, 0, 'ff121eb9-c46a-459a-9564-d79270cbee6d'),
('05bfd5df-5ea8-46d6-9915-332a294c4fed', 'Tim', 'Harris', 'john88@example.com', 'scrypt:32768:8:1$lfY8hZgmDfLSjXIi$9146132b8df85771e0264965024710ca96804111d5fef88a8811cb181a77e2d171e1ba5018e00b498e6bbc6b65b8b8c289a0d21c11824b3c85f1af46f3956537', 'profile_57.jpg', 1732898999, 0, 0, 0, 0, 'a9a35f6b-3a89-43f2-b674-522adc0cd7b4'),
('09b3560b-f663-4262-8000-27f066bfeeaa', 'Isaac', 'Moon', 'dnelson@example.org', 'scrypt:32768:8:1$lfY8hZgmDfLSjXIi$9146132b8df85771e0264965024710ca96804111d5fef88a8811cb181a77e2d171e1ba5018e00b498e6bbc6b65b8b8c289a0d21c11824b3c85f1af46f3956537', 'profile_25.jpg', 1732898999, 0, 0, 0, 0, '025cacfb-dc58-404f-83a5-a7c2d8df5013'),
('12f50190-d6fd-457b-b46a-b83dd2d55167', 'Michael', 'Smith', 'robinroberts@testsite.org', 'scrypt:32768:8:1$RVtKgS91KREyUvJD$7d443b51c3638e8c36e32fe3a6bd35cce7bcddacd01ce1fd63e61531de51275e3c61ce97f1ad23744660ff61885b3f7c8d2f24af6e65208174b0d4b021b2fdbc', 'profile_35.jpg', 1732898999, 0, 0, 0, 1732898999, '17d759bd-6d0c-41b7-8284-b6a5e12ba534'),
('13a6a7ea-3f71-4a09-98d2-a795a31e25d0', 'Heather', '', 'coreymiller@example.com', 'scrypt:32768:8:1$zvkwTs5W1MN7HrKK$890deb17c583fc7ff33366a197a636e49793e3b2ced59a7bae16d0d5235d2c2c7cc13b4c243006c2c6f3436a74fd06fe8a3f9fa6ee587a2c52a976238e30de40', 'profile_26.jpg', 1732898999, 0, 0, 0, 1732898999, 'c7a3fa0e-fe3d-4fc3-b537-13c9dcdbe6e4'),
('184990c6-2b42-4ce0-a185-887f7c3afd28', 'Michael', '', 'efletcher@example.net', 'scrypt:32768:8:1$zvkwTs5W1MN7HrKK$890deb17c583fc7ff33366a197a636e49793e3b2ced59a7bae16d0d5235d2c2c7cc13b4c243006c2c6f3436a74fd06fe8a3f9fa6ee587a2c52a976238e30de40', 'profile_47.jpg', 1732898999, 0, 0, 0, 1732898999, '3eb528d1-895e-4352-9f4f-47a938a87f5c'),
('27547afd-1941-4308-a6c9-f2d6c53b753a', 'Bryan', '', 'lcarroll@example.net', 'scrypt:32768:8:1$zvkwTs5W1MN7HrKK$890deb17c583fc7ff33366a197a636e49793e3b2ced59a7bae16d0d5235d2c2c7cc13b4c243006c2c6f3436a74fd06fe8a3f9fa6ee587a2c52a976238e30de40', 'profile_7.jpg', 1732898999, 0, 0, 0, 1732898999, '4c93ade4-03d3-42f6-b158-6fdd538b8199'),
('2a6c044a-85e3-4d8e-8749-5065c1fc9838', 'Stacy', 'Little', 'anthony62@example.org', 'scrypt:32768:8:1$lfY8hZgmDfLSjXIi$9146132b8df85771e0264965024710ca96804111d5fef88a8811cb181a77e2d171e1ba5018e00b498e6bbc6b65b8b8c289a0d21c11824b3c85f1af46f3956537', 'profile_92.jpg', 1732898999, 0, 0, 0, 1732898999, 'fc8416ec-dded-46a4-9a21-0970dc0e11bd'),
('2b6bf046-40ef-4f1d-adf3-07b7bd6e1a5d', 'Travis', '', 'jesusmcdonald@example.net', 'scrypt:32768:8:1$zvkwTs5W1MN7HrKK$890deb17c583fc7ff33366a197a636e49793e3b2ced59a7bae16d0d5235d2c2c7cc13b4c243006c2c6f3436a74fd06fe8a3f9fa6ee587a2c52a976238e30de40', 'profile_55.jpg', 1732898999, 0, 0, 0, 1732898999, '2138527a-9c5e-4f11-a42c-85bd2b93870a'),
('2b757ede-a315-4a3a-b637-c58969936269', 'James', '', 'fdaniels@example.org', 'scrypt:32768:8:1$zvkwTs5W1MN7HrKK$890deb17c583fc7ff33366a197a636e49793e3b2ced59a7bae16d0d5235d2c2c7cc13b4c243006c2c6f3436a74fd06fe8a3f9fa6ee587a2c52a976238e30de40', 'profile_8.jpg', 1732898999, 0, 0, 0, 1732898999, '5d352354-e243-4fd8-87ec-10a95e7111a4'),
('2e740fe3-87ef-40fe-8c03-523a6be3183a', 'Alex', 'Williams', 'mosssean@fakemail.io', 'scrypt:32768:8:1$RVtKgS91KREyUvJD$7d443b51c3638e8c36e32fe3a6bd35cce7bcddacd01ce1fd63e61531de51275e3c61ce97f1ad23744660ff61885b3f7c8d2f24af6e65208174b0d4b021b2fdbc', 'profile_51.jpg', 1732898999, 0, 0, 0, 0, '4c0524b7-cc4b-4b75-a25f-719779626d8a'),
('3479aa87-6ed9-4437-8258-d5f79e2f07d0', 'Audrey', 'Bailey', 'cirwin@example.net', 'scrypt:32768:8:1$lfY8hZgmDfLSjXIi$9146132b8df85771e0264965024710ca96804111d5fef88a8811cb181a77e2d171e1ba5018e00b498e6bbc6b65b8b8c289a0d21c11824b3c85f1af46f3956537', 'profile_90.jpg', 1732898999, 0, 0, 0, 1732898999, '81321ecd-1f62-4840-8200-343f280a759e'),
('380b1aec-1d42-472e-8d07-32d406291394', 'Robert', '', 'zroberts@example.net', 'scrypt:32768:8:1$zvkwTs5W1MN7HrKK$890deb17c583fc7ff33366a197a636e49793e3b2ced59a7bae16d0d5235d2c2c7cc13b4c243006c2c6f3436a74fd06fe8a3f9fa6ee587a2c52a976238e30de40', 'profile_79.jpg', 1732898999, 0, 0, 0, 1732898999, 'fcbbd887-f402-4d1b-9024-c5edd2386097'),
('38294873-0bff-444f-b1d9-b6a3e4fcd481', 'Elizabeth', '', 'erica70@example.org', 'scrypt:32768:8:1$zvkwTs5W1MN7HrKK$890deb17c583fc7ff33366a197a636e49793e3b2ced59a7bae16d0d5235d2c2c7cc13b4c243006c2c6f3436a74fd06fe8a3f9fa6ee587a2c52a976238e30de40', 'profile_16.jpg', 1732898999, 0, 0, 0, 1732898999, '3d66e555-234e-4c54-9f68-fed6caaabf85'),
('4218788d-03b7-4812-bd7d-31c8859e92d8', 'John', 'Customer', 'customer@fulldemo.com', 'scrypt:32768:8:1$etWJw95vkjMnM3RX$089c77d0a8829c04cb38a40a78f0160b82579031e490bed19c646e8de673cf092e5931384bf3c9da077ca0336df1381f2ebcf09234e1642f0007cebc44932cdd', 'profile_11.jpg', 1732898999, 0, 0, 0, 1732898999, '08e5ce3e-369b-4e19-a561-71490d58594d'),
('519fb7fe-b973-44b2-8214-3880d2739ed1', 'Donna', 'Romero', 'vcontreras@example.com', 'scrypt:32768:8:1$lfY8hZgmDfLSjXIi$9146132b8df85771e0264965024710ca96804111d5fef88a8811cb181a77e2d171e1ba5018e00b498e6bbc6b65b8b8c289a0d21c11824b3c85f1af46f3956537', 'profile_26.jpg', 1732898999, 0, 0, 0, 0, '412a1f30-0e74-4a2b-9edf-3b837092bb54'),
('59fd3924-eb54-4b19-9b7a-e54464ac0ace', 'John', 'Wright', 'jonathansmith@example.org', 'scrypt:32768:8:1$lfY8hZgmDfLSjXIi$9146132b8df85771e0264965024710ca96804111d5fef88a8811cb181a77e2d171e1ba5018e00b498e6bbc6b65b8b8c289a0d21c11824b3c85f1af46f3956537', 'profile_99.jpg', 1732898999, 0, 0, 0, 0, 'eb24361e-853f-4c8c-8991-7231cef4a540'),
('60ddf8fc-996b-416c-81ae-203a6e78b4d6', 'Bryan', 'Wong', 'micheleclark@mydomain.net', 'scrypt:32768:8:1$RVtKgS91KREyUvJD$7d443b51c3638e8c36e32fe3a6bd35cce7bcddacd01ce1fd63e61531de51275e3c61ce97f1ad23744660ff61885b3f7c8d2f24af6e65208174b0d4b021b2fdbc', 'profile_10.jpg', 1732898999, 0, 0, 0, 1732898999, 'a6dd2b31-e1ae-4687-92a3-d8b8fe5e11b8'),
('62939ddb-e995-4b26-8c37-f09eca55a263', 'John', 'Partner', 'partner@fulldemo.com', 'scrypt:32768:8:1$bqS81LxQTNxZy5nL$aa34633f8647f00ce559935f5d9242b118ab9911d15e8835dc8cda726ee1882853eb41cf04610ffca1f7772fe894a3b578925e66a4262ea2ae1e09dabd72cd7d', 'profile_12.jpg', 1732898999, 0, 0, 0, 1732898999, 'def413d1-fe4f-4003-9728-b4fc603541f7'),
('65b8112b-20f1-4296-80af-ec1bcec8adc4', 'Dana', 'Wilson', 'vbauer@example.com', 'scrypt:32768:8:1$RVtKgS91KREyUvJD$7d443b51c3638e8c36e32fe3a6bd35cce7bcddacd01ce1fd63e61531de51275e3c61ce97f1ad23744660ff61885b3f7c8d2f24af6e65208174b0d4b021b2fdbc', 'profile_54.jpg', 1732898999, 0, 0, 0, 0, '2597916d-f029-4310-b09b-1945bd35a4bb'),
('6cb7edb3-a661-4bf5-88b5-332059834722', 'Daniel', '', 'ohall@example.com', 'scrypt:32768:8:1$zvkwTs5W1MN7HrKK$890deb17c583fc7ff33366a197a636e49793e3b2ced59a7bae16d0d5235d2c2c7cc13b4c243006c2c6f3436a74fd06fe8a3f9fa6ee587a2c52a976238e30de40', 'profile_5.jpg', 1732898999, 0, 0, 0, 0, '48030a42-2f40-4847-abc5-ed0992273109'),
('6eddcea3-edff-455e-858f-e858bc2000a6', 'Eric', 'Webster', 'ashlee41@fakemail.io', 'scrypt:32768:8:1$RVtKgS91KREyUvJD$7d443b51c3638e8c36e32fe3a6bd35cce7bcddacd01ce1fd63e61531de51275e3c61ce97f1ad23744660ff61885b3f7c8d2f24af6e65208174b0d4b021b2fdbc', 'profile_48.jpg', 1732898999, 0, 0, 0, 0, '077be005-10b3-4832-b006-70af1708d3b0'),
('71fdb80a-e6c1-487e-852c-df99edbd9934', 'Savannah', '', 'ythompson@example.net', 'scrypt:32768:8:1$zvkwTs5W1MN7HrKK$890deb17c583fc7ff33366a197a636e49793e3b2ced59a7bae16d0d5235d2c2c7cc13b4c243006c2c6f3436a74fd06fe8a3f9fa6ee587a2c52a976238e30de40', 'profile_55.jpg', 1732898999, 0, 0, 0, 0, '9d1b1b17-79a1-46a5-9e07-1de58eb95fac'),
('80ace2dc-2043-45ff-9ec9-87db1c0a84d5', 'Santiago', 'Donoso', 'admin@fulldemo.com', 'scrypt:32768:8:1$8tq7WQ6DMnATuJJs$d0f8e2910ecc81e4ec1e3d558345e5a671139f16c91f51ae244c03623ec2d2e2ec2d6ed5b0ceec3c06eba84f3838dc66d9293e3f5916cc42c1b4f2d4cbb92c73', 'profile_10.jpg', 1732898998, 0, 0, 0, 1732898998, 'b3996e95-805b-49fa-854f-3bac0e897617'),
('81fc7756-2d9a-4633-8d9c-a24bd1069a85', 'Bradley', 'Garcia', 'walkerdeborah@fakemail.io', 'scrypt:32768:8:1$RVtKgS91KREyUvJD$7d443b51c3638e8c36e32fe3a6bd35cce7bcddacd01ce1fd63e61531de51275e3c61ce97f1ad23744660ff61885b3f7c8d2f24af6e65208174b0d4b021b2fdbc', 'profile_41.jpg', 1732898999, 0, 0, 0, 1732898999, '843411e1-6632-40b2-9ac9-35806ebdf315'),
('a83269ca-6b64-435f-a0a5-a934cfc29881', 'Cynthia', 'Jacobson', 'elizabethkelley@example.com', 'scrypt:32768:8:1$lfY8hZgmDfLSjXIi$9146132b8df85771e0264965024710ca96804111d5fef88a8811cb181a77e2d171e1ba5018e00b498e6bbc6b65b8b8c289a0d21c11824b3c85f1af46f3956537', 'profile_73.jpg', 1732898999, 0, 0, 0, 0, 'c6b3f1a1-421e-42e1-83bc-a9f6cb5b0316'),
('b2919d8b-d54d-41ef-a177-d62d37966f54', 'Carmen', 'Guzman', 'johncrane@example.org', 'scrypt:32768:8:1$lfY8hZgmDfLSjXIi$9146132b8df85771e0264965024710ca96804111d5fef88a8811cb181a77e2d171e1ba5018e00b498e6bbc6b65b8b8c289a0d21c11824b3c85f1af46f3956537', 'profile_46.jpg', 1732898999, 0, 1732899277, 0, 1732898999, '69175706-4eaa-4cf7-bc1b-7553d4644130'),
('ba26f84b-dd6f-4f20-9858-af73aa20789a', 'Julian', 'Reed', 'jbecker@hotmail.com', 'scrypt:32768:8:1$RVtKgS91KREyUvJD$7d443b51c3638e8c36e32fe3a6bd35cce7bcddacd01ce1fd63e61531de51275e3c61ce97f1ad23744660ff61885b3f7c8d2f24af6e65208174b0d4b021b2fdbc', 'profile_91.jpg', 1732898999, 0, 0, 0, 1732898999, 'e5e1827f-0d38-4519-ae2e-3aa5e48fe988'),
('c30e8ab7-0fef-4579-9c51-b7553016f6f9', 'Benjamin', 'Johnson', 'bowersjames@gmail.com', 'scrypt:32768:8:1$RVtKgS91KREyUvJD$7d443b51c3638e8c36e32fe3a6bd35cce7bcddacd01ce1fd63e61531de51275e3c61ce97f1ad23744660ff61885b3f7c8d2f24af6e65208174b0d4b021b2fdbc', 'profile_73.jpg', 1732898999, 0, 0, 0, 0, '4ad77b94-af63-48e1-8247-fbec70bf2cd9'),
('c49eb763-5d1a-4564-8112-49d0b52abaa2', 'Andrew', 'Coffey', 'michaelbeck@example.com', 'scrypt:32768:8:1$lfY8hZgmDfLSjXIi$9146132b8df85771e0264965024710ca96804111d5fef88a8811cb181a77e2d171e1ba5018e00b498e6bbc6b65b8b8c289a0d21c11824b3c85f1af46f3956537', 'profile_15.jpg', 1732898999, 0, 0, 0, 0, 'f942b659-cd72-482c-9530-a612b5c67429'),
('d86781de-b164-43ad-9713-05a5ab8ad123', 'Antonio', 'Bowen', 'andrew65@example.org', 'scrypt:32768:8:1$lfY8hZgmDfLSjXIi$9146132b8df85771e0264965024710ca96804111d5fef88a8811cb181a77e2d171e1ba5018e00b498e6bbc6b65b8b8c289a0d21c11824b3c85f1af46f3956537', 'profile_10.jpg', 1732898999, 0, 0, 0, 1732898999, '6ec292e6-ac92-4197-b9ce-106ae94dc5f5'),
('de7e56bb-4f62-47fe-b7b0-9e9001aafd46', 'John', 'Restaurant', 'restaurant@fulldemo.com', 'scrypt:32768:8:1$8Iz2NV3f49zkPUOZ$74db1cf994a7768a1b47d8e84448a6555cf0c6b975fc5bc3900ffaacd01c7e7cea5e2536945164c498ba10a397f2558e40528a443d9805f90b775307908e67f5', 'profile_13.jpg', 1732898999, 0, 0, 0, 1732898999, '8c1f00e8-769e-41bc-b175-ac62d48db457'),
('e0a358c5-9934-4227-a663-2639747f947c', 'Carol', 'Houston', 'curtisdoyle@website.co', 'scrypt:32768:8:1$RVtKgS91KREyUvJD$7d443b51c3638e8c36e32fe3a6bd35cce7bcddacd01ce1fd63e61531de51275e3c61ce97f1ad23744660ff61885b3f7c8d2f24af6e65208174b0d4b021b2fdbc', 'profile_23.jpg', 1732898999, 0, 0, 0, 0, '0020e764-5513-4266-a8d0-89813a96c6b9'),
('e8a62b62-bdba-4222-9aa4-28c64b24c52f', 'Michael', '', 'qstephenson@example.org', 'scrypt:32768:8:1$zvkwTs5W1MN7HrKK$890deb17c583fc7ff33366a197a636e49793e3b2ced59a7bae16d0d5235d2c2c7cc13b4c243006c2c6f3436a74fd06fe8a3f9fa6ee587a2c52a976238e30de40', 'profile_77.jpg', 1732898999, 0, 0, 0, 1732898999, 'ba97f696-9234-42c1-a320-cd7b5dde1e6c');

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
('80ace2dc-2043-45ff-9ec9-87db1c0a84d5', '16fd2706-8baf-433b-82eb-8c7fada847da'),
('13a6a7ea-3f71-4a09-98d2-a795a31e25d0', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('184990c6-2b42-4ce0-a185-887f7c3afd28', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('27547afd-1941-4308-a6c9-f2d6c53b753a', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('2b6bf046-40ef-4f1d-adf3-07b7bd6e1a5d', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('2b757ede-a315-4a3a-b637-c58969936269', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('380b1aec-1d42-472e-8d07-32d406291394', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('38294873-0bff-444f-b1d9-b6a3e4fcd481', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('6cb7edb3-a661-4bf5-88b5-332059834722', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('71fdb80a-e6c1-487e-852c-df99edbd9934', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('de7e56bb-4f62-47fe-b7b0-9e9001aafd46', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('e8a62b62-bdba-4222-9aa4-28c64b24c52f', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('03c8a049-51e1-4f2c-b42b-eca43bccd50b', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('12f50190-d6fd-457b-b46a-b83dd2d55167', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('2e740fe3-87ef-40fe-8c03-523a6be3183a', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('4218788d-03b7-4812-bd7d-31c8859e92d8', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('60ddf8fc-996b-416c-81ae-203a6e78b4d6', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('65b8112b-20f1-4296-80af-ec1bcec8adc4', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('6eddcea3-edff-455e-858f-e858bc2000a6', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('81fc7756-2d9a-4633-8d9c-a24bd1069a85', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('ba26f84b-dd6f-4f20-9858-af73aa20789a', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('c30e8ab7-0fef-4579-9c51-b7553016f6f9', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('e0a358c5-9934-4227-a663-2639747f947c', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('05bfd5df-5ea8-46d6-9915-332a294c4fed', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('09b3560b-f663-4262-8000-27f066bfeeaa', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('2a6c044a-85e3-4d8e-8749-5065c1fc9838', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('3479aa87-6ed9-4437-8258-d5f79e2f07d0', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('519fb7fe-b973-44b2-8214-3880d2739ed1', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('59fd3924-eb54-4b19-9b7a-e54464ac0ace', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('62939ddb-e995-4b26-8c37-f09eca55a263', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('a83269ca-6b64-435f-a0a5-a934cfc29881', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('b2919d8b-d54d-41ef-a177-d62d37966f54', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('c49eb763-5d1a-4564-8112-49d0b52abaa2', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('d86781de-b164-43ad-9713-05a5ab8ad123', 'f47ac10b-58cc-4372-a567-0e02b2c3d479');

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
