-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Vært: mysql
-- Genereringstid: 07. 12 2024 kl. 18:31:00
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
('02409c5c-5e89-4b63-9dde-3bb8b05a9c74', '96c21938-1602-44a8-955c-6f710ddddf14', 'Chicken Shawarma', 807.99, 'dish_78.jpg', 'dish_78.jpg', 'dish_78.jpg', 1733596217, 0, 0, 0),
('0396abe5-4ce2-4bee-887d-b68a2a164a0a', '02b2a30b-21cd-4cd1-9cf6-d520ee36ef16', 'Cordon Bleu', 898.90, 'dish_46.jpg', 'dish_46.jpg', 'dish_46.jpg', 1733596217, 0, 0, 0),
('053b7688-add1-4242-8538-b7f29afca92a', '0060d96a-e7fb-4b73-9ee1-8310ebc329fc', 'Moussaka', 595.51, 'dish_85.jpg', 'dish_85.jpg', 'dish_85.jpg', 1733596217, 0, 0, 0),
('11370893-2731-4253-8516-b774ee7db8a6', '61827499-8411-43bf-beaa-6ccf9e50a352', 'Peking Duck', 837.61, 'dish_73.jpg', 'dish_73.jpg', 'dish_73.jpg', 1733596217, 0, 0, 0),
('2857e93d-0ff1-4427-a123-9bc9cb142d3f', '0b6818c6-a857-4a35-88f1-af8953ec3215', 'Pesto Pasta', 820.62, 'dish_100.jpg', 'dish_100.jpg', 'dish_100.jpg', 1733596217, 0, 0, 0),
('2977fbc5-edd8-4f00-9598-d9d4bf00b4f3', 'd942107e-298c-451f-8db7-8987921a7dbb', 'Paella', 626.94, 'dish_98.jpg', 'dish_98.jpg', 'dish_98.jpg', 1733596217, 0, 0, 0),
('29bba906-df1d-484d-bfa9-5ddf9e963806', '61827499-8411-43bf-beaa-6ccf9e50a352', 'Bangers and Mash', 727.68, 'dish_91.jpg', 'dish_91.jpg', 'dish_91.jpg', 1733596217, 0, 0, 0),
('2b8f61a2-9ade-4f2f-a595-4944eb9051c0', '0060d96a-e7fb-4b73-9ee1-8310ebc329fc', 'Lasagna', 934.08, 'dish_66.jpg', 'dish_66.jpg', 'dish_66.jpg', 1733596217, 0, 0, 0),
('3029aca3-0310-4713-b9cb-e35b552413bd', '4007e305-4969-4d61-8e46-fb53e2352ec9', 'Clafoutis', 657.49, 'dish_39.jpg', 'dish_39.jpg', 'dish_39.jpg', 1733596217, 0, 0, 0),
('324421a4-5f78-46ab-80a2-ea8905ef6823', '4007e305-4969-4d61-8e46-fb53e2352ec9', 'Lamb Tagine', 918.41, 'dish_24.jpg', 'dish_24.jpg', 'dish_24.jpg', 1733596217, 0, 0, 0),
('335f91a2-0d02-4d70-ba9d-d28dc883d916', '61827499-8411-43bf-beaa-6ccf9e50a352', 'Burrito', 727.85, 'dish_81.jpg', 'dish_81.jpg', 'dish_81.jpg', 1733596217, 0, 0, 0),
('3560fc3f-0aa2-4663-b38a-932711db0d1c', 'd942107e-298c-451f-8db7-8987921a7dbb', 'Hummus', 921.05, 'dish_41.jpg', 'dish_41.jpg', 'dish_41.jpg', 1733596217, 0, 0, 0),
('4441a2cb-1340-4a5e-ba1f-6dfe8fdee095', '87a0fcb1-026e-4c30-9770-002fca5d6929', 'Pappardelle', 774.57, 'dish_17.jpg', 'dish_17.jpg', 'dish_17.jpg', 1733596217, 0, 0, 0),
('50c95f7b-182f-4519-a4f4-06817ee8cb53', '0bbfb6f2-1549-452e-ab63-3d719daaaf3f', 'Beef Stroganoff', 960.17, 'dish_93.jpg', 'dish_93.jpg', 'dish_93.jpg', 1733596217, 0, 0, 0),
('53acf844-9764-4cae-b3cd-df9834c8790c', '0b6818c6-a857-4a35-88f1-af8953ec3215', 'Pork Ribs', 561.49, 'dish_21.jpg', 'dish_21.jpg', 'dish_21.jpg', 1733596217, 0, 0, 0),
('55cca059-eaa5-4eb5-9498-d38fa1c3c8d4', '0bbfb6f2-1549-452e-ab63-3d719daaaf3f', 'Pork Ribs', 930.76, 'dish_62.jpg', 'dish_62.jpg', 'dish_62.jpg', 1733596217, 0, 0, 0),
('592deda5-9e6f-4116-8e5a-0402e796e5e6', 'c9ef0a32-3595-4729-9762-7c6989bd6427', 'Empanadas de Pollo', 795.11, 'dish_13.jpg', 'dish_13.jpg', 'dish_13.jpg', 1733596217, 0, 0, 0),
('59e733f2-eb7a-4f31-80bc-e6cad0fd7a34', '0b6818c6-a857-4a35-88f1-af8953ec3215', 'Ragu', 643.70, 'dish_92.jpg', 'dish_92.jpg', 'dish_92.jpg', 1733596217, 0, 0, 0),
('5a42327b-da1f-473d-a5a1-5398bcbc4155', '0b6818c6-a857-4a35-88f1-af8953ec3215', 'Tandoori Chicken', 940.85, 'dish_85.jpg', 'dish_85.jpg', 'dish_85.jpg', 1733596217, 0, 0, 0),
('5def121c-937c-4370-8e55-8718fa92fb03', '4007e305-4969-4d61-8e46-fb53e2352ec9', 'Ceviche', 946.04, 'dish_19.jpg', 'dish_19.jpg', 'dish_19.jpg', 1733596217, 0, 0, 0),
('61292164-619c-4a1c-9ec3-70fc590f41e9', '96c21938-1602-44a8-955c-6f710ddddf14', 'Mango Sticky Rice', 500.70, 'dish_86.jpg', 'dish_86.jpg', 'dish_86.jpg', 1733596217, 0, 0, 0),
('689d8eb5-d48c-411f-886c-24dc381c65ca', '02b2a30b-21cd-4cd1-9cf6-d520ee36ef16', 'Crab Cakes', 559.48, 'dish_74.jpg', 'dish_74.jpg', 'dish_74.jpg', 1733596217, 0, 0, 0),
('6c9b5232-b336-4290-a4f3-4b836fa5f501', '61827499-8411-43bf-beaa-6ccf9e50a352', 'Dim Sum', 813.84, 'dish_15.jpg', 'dish_15.jpg', 'dish_15.jpg', 1733596217, 0, 0, 0),
('75762d91-d260-4b52-b441-978aca50a79d', 'c9ef0a32-3595-4729-9762-7c6989bd6427', 'Schnitzel', 927.34, 'dish_28.jpg', 'dish_28.jpg', 'dish_28.jpg', 1733596217, 0, 0, 0),
('777d8b97-975b-4511-844e-050c5c429964', 'd942107e-298c-451f-8db7-8987921a7dbb', 'Tortilla Española', 633.82, 'dish_18.jpg', 'dish_18.jpg', 'dish_18.jpg', 1733596217, 0, 0, 0),
('7825cc9f-4711-449a-8ca9-25e66b14c5a9', '0bbfb6f2-1549-452e-ab63-3d719daaaf3f', 'Mole Poblano', 899.74, 'dish_98.jpg', 'dish_98.jpg', 'dish_98.jpg', 1733596217, 0, 0, 0),
('7be416c1-edca-461c-807f-c872f41515fe', '0060d96a-e7fb-4b73-9ee1-8310ebc329fc', 'Lobster Roll', 912.56, 'dish_10.jpg', 'dish_10.jpg', 'dish_10.jpg', 1733596217, 0, 0, 0),
('7d3c10d4-3a22-44b2-82e7-6d4d4c8b46f8', '87a0fcb1-026e-4c30-9770-002fca5d6929', 'Gnocchi', 782.86, 'dish_80.jpg', 'dish_80.jpg', 'dish_80.jpg', 1733596217, 0, 0, 0),
('84c5f783-ef25-4367-b8e4-3a8ed4c6a2d0', 'c9ef0a32-3595-4729-9762-7c6989bd6427', 'Tandoori Chicken', 767.14, 'dish_42.jpg', 'dish_42.jpg', 'dish_42.jpg', 1733596217, 0, 0, 0),
('88551aa0-4925-4d6c-a53a-fccbea93914e', '4007e305-4969-4d61-8e46-fb53e2352ec9', 'Peking Duck', 822.72, 'dish_80.jpg', 'dish_80.jpg', 'dish_80.jpg', 1733596217, 0, 0, 0),
('89eb5a56-60b1-4ce3-96fe-2c5080d00601', 'c9ef0a32-3595-4729-9762-7c6989bd6427', 'Fish and Chips', 767.47, 'dish_80.jpg', 'dish_80.jpg', 'dish_80.jpg', 1733596217, 0, 0, 0),
('8ab68421-f4c8-465b-92d0-2a3f082d4957', '0bbfb6f2-1549-452e-ab63-3d719daaaf3f', 'Paella Valenciana', 796.39, 'dish_79.jpg', 'dish_79.jpg', 'dish_79.jpg', 1733596217, 0, 0, 0),
('8c09eb52-f4a6-467f-ad14-320bf1aef97b', '0060d96a-e7fb-4b73-9ee1-8310ebc329fc', 'Beef Burritos', 853.26, 'dish_53.jpg', 'dish_53.jpg', 'dish_53.jpg', 1733596217, 0, 0, 0),
('9199147e-8e39-4252-97b4-dbe6453625bd', '96c21938-1602-44a8-955c-6f710ddddf14', 'Tiramisu', 619.23, 'dish_75.jpg', 'dish_75.jpg', 'dish_75.jpg', 1733596217, 0, 0, 0),
('9473ff10-b579-4fec-ad2b-9582907e4667', '0b6818c6-a857-4a35-88f1-af8953ec3215', 'Falafel', 683.68, 'dish_71.jpg', 'dish_71.jpg', 'dish_71.jpg', 1733596217, 0, 0, 0),
('98cbbd76-86c1-48fa-bb78-638b70d7f98c', 'd942107e-298c-451f-8db7-8987921a7dbb', 'Stuffed Bell Peppers', 673.94, 'dish_8.jpg', 'dish_8.jpg', 'dish_8.jpg', 1733596217, 0, 0, 0),
('9a417c4a-21c5-4d28-b35f-d2c294944874', '02b2a30b-21cd-4cd1-9cf6-d520ee36ef16', 'Falafel', 666.74, 'dish_80.jpg', 'dish_80.jpg', 'dish_80.jpg', 1733596217, 0, 0, 0),
('a0332c46-4be3-4e47-a023-133af42f6e26', 'd942107e-298c-451f-8db7-8987921a7dbb', 'Blini with Caviar', 958.72, 'dish_60.jpg', 'dish_60.jpg', 'dish_60.jpg', 1733596217, 0, 0, 0),
('a622740b-b4fa-472b-ab1b-5f330011c657', '02b2a30b-21cd-4cd1-9cf6-d520ee36ef16', 'Peking Duck', 848.03, 'dish_6.jpg', 'dish_6.jpg', 'dish_6.jpg', 1733596217, 0, 0, 0),
('a795a452-5e2e-449d-918d-cb1a3cc18be4', 'c9ef0a32-3595-4729-9762-7c6989bd6427', 'Clam Chowder', 730.03, 'dish_79.jpg', 'dish_79.jpg', 'dish_79.jpg', 1733596217, 0, 0, 0),
('acbb7f63-c8f2-430d-af4c-8707f5e92b79', '0bbfb6f2-1549-452e-ab63-3d719daaaf3f', 'Paella', 934.64, 'dish_26.jpg', 'dish_26.jpg', 'dish_26.jpg', 1733596217, 0, 0, 0),
('ade9da06-c21d-4087-b454-fa02393b0e72', '87a0fcb1-026e-4c30-9770-002fca5d6929', 'Tandoori Chicken', 542.02, 'dish_15.jpg', 'dish_15.jpg', 'dish_15.jpg', 1733596217, 0, 0, 0),
('b4bbbb59-1667-45bd-acfc-9e6cdbbeb9de', '0060d96a-e7fb-4b73-9ee1-8310ebc329fc', 'Peking Duck Pancakes', 949.44, 'dish_21.jpg', 'dish_21.jpg', 'dish_21.jpg', 1733596217, 0, 0, 0),
('b89d0c20-5c13-48a6-80a3-e080b7991e77', '02b2a30b-21cd-4cd1-9cf6-d520ee36ef16', 'Cannelloni', 761.62, 'dish_92.jpg', 'dish_92.jpg', 'dish_92.jpg', 1733596217, 0, 0, 0),
('b972f2d8-3ea9-462a-9f6a-115cc65e0af1', '02b2a30b-21cd-4cd1-9cf6-d520ee36ef16', 'Crepes', 535.68, 'dish_81.jpg', 'dish_81.jpg', 'dish_81.jpg', 1733596217, 0, 0, 0),
('bd0a9a49-4dd7-4c4c-bed9-80e16134dd9d', '96c21938-1602-44a8-955c-6f710ddddf14', 'Chicken Katsu', 536.78, 'dish_68.jpg', 'dish_68.jpg', 'dish_68.jpg', 1733596217, 0, 0, 0),
('c3a4f45a-bf9e-4e8c-b75a-972f9b04fa86', '0b6818c6-a857-4a35-88f1-af8953ec3215', 'Beef Wellington', 563.89, 'dish_67.jpg', 'dish_67.jpg', 'dish_67.jpg', 1733596217, 0, 0, 0),
('c517f3b4-023e-4afa-a3d3-d8fdd36fbf1c', '96c21938-1602-44a8-955c-6f710ddddf14', 'Hamburger', 965.78, 'dish_12.jpg', 'dish_12.jpg', 'dish_12.jpg', 1733596217, 0, 0, 0),
('c6c04f08-e38d-4eba-a506-b2e36dadfd86', '0bbfb6f2-1549-452e-ab63-3d719daaaf3f', 'Moussaka', 984.54, 'dish_32.jpg', 'dish_32.jpg', 'dish_32.jpg', 1733596217, 0, 0, 0),
('ca31b5d2-17a6-4375-af21-d81fea35546f', '61827499-8411-43bf-beaa-6ccf9e50a352', 'Masala Dosa', 712.40, 'dish_38.jpg', 'dish_38.jpg', 'dish_38.jpg', 1733596217, 0, 0, 0),
('cc5d167b-fffc-45dc-891a-d893c4d326c3', '61827499-8411-43bf-beaa-6ccf9e50a352', 'Croque Monsieur', 599.15, 'dish_10.jpg', 'dish_10.jpg', 'dish_10.jpg', 1733596217, 0, 0, 0),
('d1b1e533-5d63-43fb-904b-bded495ac4ed', 'c9ef0a32-3595-4729-9762-7c6989bd6427', 'Bangers and Mash', 628.69, 'dish_26.jpg', 'dish_26.jpg', 'dish_26.jpg', 1733596217, 0, 0, 0),
('d8e72d74-782e-46be-84c3-34e209272353', '87a0fcb1-026e-4c30-9770-002fca5d6929', 'Chicken Tikka Masala', 911.51, 'dish_12.jpg', 'dish_12.jpg', 'dish_12.jpg', 1733596217, 0, 0, 0),
('e6009214-fa67-47d9-87b2-3ff05fa91edf', '87a0fcb1-026e-4c30-9770-002fca5d6929', 'Fish and Chips', 794.21, 'dish_19.jpg', 'dish_19.jpg', 'dish_19.jpg', 1733596217, 0, 0, 0),
('e85275ce-f4c7-487c-bffe-92d2c0605c12', '87a0fcb1-026e-4c30-9770-002fca5d6929', 'Tacos', 514.11, 'dish_34.jpg', 'dish_34.jpg', 'dish_34.jpg', 1733596217, 0, 0, 0),
('ee389b02-3ecc-4ab7-881b-994a702479db', '96c21938-1602-44a8-955c-6f710ddddf14', 'Lamb Tagine', 723.40, 'dish_52.jpg', 'dish_52.jpg', 'dish_52.jpg', 1733596217, 0, 0, 0),
('ef7ffbdb-16eb-42a5-a9d3-5ce6f92e1322', '0060d96a-e7fb-4b73-9ee1-8310ebc329fc', 'Pappardelle', 760.34, 'dish_41.jpg', 'dish_41.jpg', 'dish_41.jpg', 1733596217, 0, 0, 0),
('f1090f10-3ded-4ff1-915c-e0c2aa0daebe', '4007e305-4969-4d61-8e46-fb53e2352ec9', 'Chilaquiles', 698.26, 'dish_88.jpg', 'dish_88.jpg', 'dish_88.jpg', 1733596217, 0, 0, 0),
('f27507c0-241e-45f8-aa07-0d47b496b037', '27763272-712a-4d0a-b574-cad7318106a0', 'Spaghetti Carbonara', 15.99, 'dish_1.jpg', 'dish_2.jpg', 'dish_3.jpg', 1733596217, 0, 0, 0),
('f30bab06-33c1-4181-a209-9201104ffb01', '4007e305-4969-4d61-8e46-fb53e2352ec9', 'Clam Chowder', 836.88, 'dish_8.jpg', 'dish_8.jpg', 'dish_8.jpg', 1733596217, 0, 0, 0),
('fa2cf7b1-5303-42b8-99d8-9e5b468afb46', 'd942107e-298c-451f-8db7-8987921a7dbb', 'Salmon Teriyaki', 526.02, 'dish_27.jpg', 'dish_27.jpg', 'dish_27.jpg', 1733596217, 0, 0, 0);

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
  `user_created_at` int UNSIGNED DEFAULT NULL,
  `user_deleted_at` int UNSIGNED DEFAULT NULL,
  `user_blocked_at` int UNSIGNED DEFAULT NULL,
  `user_updated_at` int UNSIGNED DEFAULT NULL,
  `user_verified_at` int UNSIGNED DEFAULT NULL,
  `user_verification_key` char(36) DEFAULT NULL,
  `user_reset_password_key` char(36) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Data dump for tabellen `users`
--

INSERT INTO `users` (`user_pk`, `user_name`, `user_last_name`, `user_email`, `user_password`, `user_created_at`, `user_deleted_at`, `user_blocked_at`, `user_updated_at`, `user_verified_at`, `user_verification_key`, `user_reset_password_key`) VALUES
('0060d96a-e7fb-4b73-9ee1-8310ebc329fc', 'Crimson Oak Steakho', '', 'hoffmanbrandon@example.org', 'scrypt:32768:8:1$CdqSZ8w0TVU04sOa$350f7f9d5755d5ec9f0ba3b85d3f1808422d208d7c50d3619356645490b96a955c4ece0c896e2831cee0f7dfeab6d13996fdaa1126984897c291e58b6446fb0d', 1733596217, 0, 0, 0, 1733596217, '2dbcbade-6d74-4175-9ee3-42c51aadea47', '0'),
('02b2a30b-21cd-4cd1-9cf6-d520ee36ef16', 'Crescent Moon Caf', '', 'tinacoleman@example.com', 'scrypt:32768:8:1$CdqSZ8w0TVU04sOa$350f7f9d5755d5ec9f0ba3b85d3f1808422d208d7c50d3619356645490b96a955c4ece0c896e2831cee0f7dfeab6d13996fdaa1126984897c291e58b6446fb0d', 1733596217, 0, 0, 0, 0, '0cf3d696-db09-44f6-b5e8-80d699675c6b', '0'),
('048d5f1c-a1e7-4dd7-a40a-250ad162489e', 'JohnGlemteKoden', 'Customer', 'customer2@fulldemo.com', 'scrypt:32768:8:1$4JhvcZg7Dy79Rp5w$9e7978dc6c259f7b1b8569de485967b684ac4748c998efc1c36d40479fa9e04510c03f9b20e132727e0d2c4ebe5973c5a86f5a23a76d34809eb5ba06e9e8df2d', 1733596217, 0, 0, 0, 1733596217, 'fedeacf1-8826-417f-afb8-5612e8cd5ab7', 'dc2ed7b7-8786-41c2-a3f7-249800add5e8'),
('081317d3-f0b6-4998-9dbf-ed6b89322f7c', 'Daniel', 'Martinez', 'amanda52@hotmail.com', 'scrypt:32768:8:1$XauA8nPrKjcZ1Xtw$6eb3af3722c6616122d65b59d3b1a8d67f1a4c95aae1e579d682c6791d960b222be64bfbbc43ca1bae1d7e1acd2bed24926a89b93e4f0bccf5f625827e46978b', 1733596217, 0, 0, 0, 1733596217, 'd3b4ef18-bf6e-4b2e-b7f4-600d0659d515', '0'),
('0b6818c6-a857-4a35-88f1-af8953ec3215', 'Bayside Grill', '', 'william84@example.com', 'scrypt:32768:8:1$CdqSZ8w0TVU04sOa$350f7f9d5755d5ec9f0ba3b85d3f1808422d208d7c50d3619356645490b96a955c4ece0c896e2831cee0f7dfeab6d13996fdaa1126984897c291e58b6446fb0d', 1733596217, 0, 0, 0, 0, 'f44aef75-0ee5-44b9-8a57-fb408fbc7d4f', '0'),
('0bbfb6f2-1549-452e-ab63-3d719daaaf3f', 'Emerald Coast Bistr', '', 'chrisbaker@example.com', 'scrypt:32768:8:1$CdqSZ8w0TVU04sOa$350f7f9d5755d5ec9f0ba3b85d3f1808422d208d7c50d3619356645490b96a955c4ece0c896e2831cee0f7dfeab6d13996fdaa1126984897c291e58b6446fb0d', 1733596217, 0, 0, 0, 1733596217, 'bceab718-4ef4-4228-92bb-6b12f2062460', '0'),
('1e8047ec-5c9d-4dc0-86d7-2dd8a4fe995d', 'UnverifiedJohn', 'Customer', 'Unverifiedcustomer@fulldemo.com', 'scrypt:32768:8:1$l8s3aUcNQ70fQerV$e165c16486805e66a6cb07ea9d8de5c17fcef94367d979af1a80d57b4b8cd06e352ffc45c555a89f3052483b40282d942c94bd7f4831a0c7cf6aa54d557130f2', 1733596217, 0, 0, 0, 0, '2722bdea-432b-4f0b-b441-2a5e1dc27e66', '0'),
('27763272-712a-4d0a-b574-cad7318106a0', 'Johns Diner', 'Restaurant', 'restaurant@fulldemo.com', 'scrypt:32768:8:1$dcCJbkxBVuGHlL8f$34ce37e0a08935bf99284f7a3fbb2d8f3e6f23d116954d5224f3cf0c4f15924d418799942f56feb1f27977316674ecf6682b342dd229d3c94996ad9b6b5e94fb', 1733596217, 0, 0, 0, 1733596217, '017f62f0-4d6f-4b30-9992-27946257724a', '0'),
('3b1f6532-abf1-4d4f-8d02-61f7890ebed9', 'Santiago', 'Donoso', 'admin@fulldemo.com', 'scrypt:32768:8:1$9BBdjpJ6H9WeZD4B$f57e268e9e288b992340289dc367baf46dd15c24637459f3fd0551b4d97510108f54c5595201754e040fae1c5a78f5b953939af43ff2731926e0d4076cd2e7c2', 1733596216, 0, 0, 0, 1733596216, '17ef7ead-d6eb-4566-841e-08fee6277366', '0'),
('4007e305-4969-4d61-8e46-fb53e2352ec9', 'Emerald Coast Bistr', '', 'qroberts@example.org', 'scrypt:32768:8:1$CdqSZ8w0TVU04sOa$350f7f9d5755d5ec9f0ba3b85d3f1808422d208d7c50d3619356645490b96a955c4ece0c896e2831cee0f7dfeab6d13996fdaa1126984897c291e58b6446fb0d', 1733596217, 0, 0, 0, 1733596217, 'b0124d45-7f16-4fb5-8d19-c3105fed1c40', '0'),
('4218788d-03b7-4812-bd7d-31c8859e92d8', 'John', 'Customer', 'customer@fulldemo.com', 'scrypt:32768:8:1$ohWonF9RFRbb59QN$e6a82e88c8bfe9a6df214a34d96b8f8fad1cbd48b88f5d3e1a995e8361a4fb8c0b4a54b97036f683830db82062ec08f8a19bd8844ac798814c21fa00d57ac2e0', 1733596216, 0, 0, 0, 1733596216, 'f24d15a9-1d13-4d9c-b6ac-ec8e7e0d608a', '0'),
('43246148-3a49-4f46-a340-ffe582f55e43', 'Emily', 'Russell', 'andrewbeard@fakemail.io', 'scrypt:32768:8:1$XauA8nPrKjcZ1Xtw$6eb3af3722c6616122d65b59d3b1a8d67f1a4c95aae1e579d682c6791d960b222be64bfbbc43ca1bae1d7e1acd2bed24926a89b93e4f0bccf5f625827e46978b', 1733596217, 0, 0, 0, 0, '07fc7454-29d6-4367-becb-5b669d5fad45', '0'),
('53570d9b-a9d5-4bfc-858e-c35fda41fb81', 'William', 'Ramirez', 'nmiller@example.com', 'scrypt:32768:8:1$jzu0JBlc75nyODek$5e04b1babd50c3a41c93d159047b7527396691bd50ba3d6ff9116f3ce1ba2c4aada4e78831027faa3064a18927ca3be778bd2797fc0aba3104324beb93b4bee9', 1733596217, 0, 0, 0, 1733596217, '2725186d-63cf-4aa0-83f6-582c77464683', '0'),
('53b58561-bff9-4501-8de4-6c610d443c7a', 'Michael', 'Harmon', 'acevedodesiree@website.co', 'scrypt:32768:8:1$XauA8nPrKjcZ1Xtw$6eb3af3722c6616122d65b59d3b1a8d67f1a4c95aae1e579d682c6791d960b222be64bfbbc43ca1bae1d7e1acd2bed24926a89b93e4f0bccf5f625827e46978b', 1733596217, 0, 0, 0, 1733596217, '99c6240d-1021-4929-be82-0d0902c1512f', '0'),
('5ee931e9-efa8-4f59-8c1c-4cf3a6ce58b0', 'Michael', 'Vega', 'ashleysingh@website.co', 'scrypt:32768:8:1$XauA8nPrKjcZ1Xtw$6eb3af3722c6616122d65b59d3b1a8d67f1a4c95aae1e579d682c6791d960b222be64bfbbc43ca1bae1d7e1acd2bed24926a89b93e4f0bccf5f625827e46978b', 1733596217, 0, 0, 0, 0, 'c2f70201-edc0-476d-9aab-afdef56b22b9', '0'),
('61827499-8411-43bf-beaa-6ccf9e50a352', 'The Frosty Mug', '', 'julie68@example.com', 'scrypt:32768:8:1$CdqSZ8w0TVU04sOa$350f7f9d5755d5ec9f0ba3b85d3f1808422d208d7c50d3619356645490b96a955c4ece0c896e2831cee0f7dfeab6d13996fdaa1126984897c291e58b6446fb0d', 1733596217, 0, 0, 0, 1733596217, '605514e0-f3de-43dd-afe3-d4bb9a167ead', '0'),
('76a3208e-cdd9-43f0-b490-46075c694e0b', 'Sheena', 'Clark', 'nashsarah@example.org', 'scrypt:32768:8:1$jzu0JBlc75nyODek$5e04b1babd50c3a41c93d159047b7527396691bd50ba3d6ff9116f3ce1ba2c4aada4e78831027faa3064a18927ca3be778bd2797fc0aba3104324beb93b4bee9', 1733596217, 0, 0, 0, 0, '3e37cb92-4632-4226-912e-f5550cddeca0', '0'),
('76ab0941-b001-4ab5-b20e-fb7da053470c', 'Willie', 'Barnes', 'powellmelissa@example.org', 'scrypt:32768:8:1$jzu0JBlc75nyODek$5e04b1babd50c3a41c93d159047b7527396691bd50ba3d6ff9116f3ce1ba2c4aada4e78831027faa3064a18927ca3be778bd2797fc0aba3104324beb93b4bee9', 1733596217, 0, 0, 0, 0, 'a840be11-3d2b-427f-bea9-46caa5b04301', '0'),
('808dfe5b-44af-4b53-adda-e8a020bcfca0', 'Jennifer', 'Patton', 'kdiaz@gmail.com', 'scrypt:32768:8:1$XauA8nPrKjcZ1Xtw$6eb3af3722c6616122d65b59d3b1a8d67f1a4c95aae1e579d682c6791d960b222be64bfbbc43ca1bae1d7e1acd2bed24926a89b93e4f0bccf5f625827e46978b', 1733596217, 0, 0, 0, 1733596217, '7b02861f-7b11-4a4b-98eb-fa0a4dbd4a55', '0'),
('87087305-748e-4bb4-9357-4d9a1dc3e68b', 'Christopher', 'Flores', 'tabbott@example.com', 'scrypt:32768:8:1$jzu0JBlc75nyODek$5e04b1babd50c3a41c93d159047b7527396691bd50ba3d6ff9116f3ce1ba2c4aada4e78831027faa3064a18927ca3be778bd2797fc0aba3104324beb93b4bee9', 1733596217, 0, 0, 0, 0, '588437cf-4a75-4973-8de3-f94d72e26103', '0'),
('87a0fcb1-026e-4c30-9770-002fca5d6929', 'Hidden Gem Diner', '', 'ashleetaylor@example.net', 'scrypt:32768:8:1$CdqSZ8w0TVU04sOa$350f7f9d5755d5ec9f0ba3b85d3f1808422d208d7c50d3619356645490b96a955c4ece0c896e2831cee0f7dfeab6d13996fdaa1126984897c291e58b6446fb0d', 1733596217, 0, 0, 0, 0, '91879c03-af46-4b8d-a4bb-6d4c24222247', '0'),
('8ef6a2e0-5a73-4cc9-a1df-54212fe117c9', 'Rebecca', 'Johnson', 'jack36@example.org', 'scrypt:32768:8:1$jzu0JBlc75nyODek$5e04b1babd50c3a41c93d159047b7527396691bd50ba3d6ff9116f3ce1ba2c4aada4e78831027faa3064a18927ca3be778bd2797fc0aba3104324beb93b4bee9', 1733596217, 0, 0, 0, 1733596217, '16fad826-03a5-439d-b68f-7378f910e352', '0'),
('96c21938-1602-44a8-955c-6f710ddddf14', 'Crimson Flame Gril', '', 'tiffanyquinn@example.org', 'scrypt:32768:8:1$CdqSZ8w0TVU04sOa$350f7f9d5755d5ec9f0ba3b85d3f1808422d208d7c50d3619356645490b96a955c4ece0c896e2831cee0f7dfeab6d13996fdaa1126984897c291e58b6446fb0d', 1733596217, 0, 0, 0, 0, '3a9572a6-e520-41a7-ae8f-f6b99a68e33f', '0'),
('96e2588c-02f8-4fcb-943f-f2e8899467cb', 'Steven', 'Holmes', 'donald49@example.net', 'scrypt:32768:8:1$jzu0JBlc75nyODek$5e04b1babd50c3a41c93d159047b7527396691bd50ba3d6ff9116f3ce1ba2c4aada4e78831027faa3064a18927ca3be778bd2797fc0aba3104324beb93b4bee9', 1733596217, 0, 0, 0, 1733596217, '533560a0-6470-46ef-86a4-77bcc701ca20', '0'),
('aa8875aa-c937-4d44-9f9a-24d392a1d2ee', 'Alexander', 'Berry', 'ytaylor@example.net', 'scrypt:32768:8:1$jzu0JBlc75nyODek$5e04b1babd50c3a41c93d159047b7527396691bd50ba3d6ff9116f3ce1ba2c4aada4e78831027faa3064a18927ca3be778bd2797fc0aba3104324beb93b4bee9', 1733596217, 0, 0, 0, 1733596217, '99c3f778-ce55-4359-a283-e740556d923b', '0'),
('ab652729-5e74-4379-aa5f-7c643f2b7fdd', 'Sandra', 'Oneill', 'ffitzgerald@example.com', 'scrypt:32768:8:1$jzu0JBlc75nyODek$5e04b1babd50c3a41c93d159047b7527396691bd50ba3d6ff9116f3ce1ba2c4aada4e78831027faa3064a18927ca3be778bd2797fc0aba3104324beb93b4bee9', 1733596217, 0, 0, 0, 0, '92fe7282-801a-4c74-9de5-fd8e7fafef37', '0'),
('b210a83c-89d3-49e5-9c1a-e15af85f19b3', 'Eric', 'Melton', 'lblevins@website.co', 'scrypt:32768:8:1$XauA8nPrKjcZ1Xtw$6eb3af3722c6616122d65b59d3b1a8d67f1a4c95aae1e579d682c6791d960b222be64bfbbc43ca1bae1d7e1acd2bed24926a89b93e4f0bccf5f625827e46978b', 1733596217, 0, 0, 0, 0, '4d2b7c25-4ed0-4bb2-b500-855da6c279fa', '0'),
('b38fa0dd-16c2-4fbf-a7c9-8e5956578064', 'John', 'Partner', 'partner@fulldemo.com', 'scrypt:32768:8:1$eOGun1vCYxaXToka$846a99ba0b20642c441fb11d03f50a81de7d29f9f76cde11168aedc9e715b501636057a2378c6cdc2ec9b67487de3cfa3089fb9b0fd4532d950884a3ba3be3de', 1733596217, 0, 0, 0, 1733596217, '8eb47870-b86f-4314-a612-ac68bbeaf0f7', '0'),
('b67caed1-6437-4164-be00-861cb8d664c9', 'Allison', 'Baker', 'wolfmichelle@website.co', 'scrypt:32768:8:1$XauA8nPrKjcZ1Xtw$6eb3af3722c6616122d65b59d3b1a8d67f1a4c95aae1e579d682c6791d960b222be64bfbbc43ca1bae1d7e1acd2bed24926a89b93e4f0bccf5f625827e46978b', 1733596217, 0, 0, 0, 0, '1ce18aa5-8f37-4583-ae55-2016f8b929f9', '0'),
('c1dfbe76-4b3a-42d5-8049-0f0e274da67e', 'Chad', 'Hess', 'christian93@mydomain.net', 'scrypt:32768:8:1$XauA8nPrKjcZ1Xtw$6eb3af3722c6616122d65b59d3b1a8d67f1a4c95aae1e579d682c6791d960b222be64bfbbc43ca1bae1d7e1acd2bed24926a89b93e4f0bccf5f625827e46978b', 1733596217, 0, 0, 0, 0, 'e5e2fae4-89aa-44b8-83b5-8f54b4097ae5', '0'),
('c9ef0a32-3595-4729-9762-7c6989bd6427', 'Aspen Heights Cafe', '', 'wharmon@example.com', 'scrypt:32768:8:1$CdqSZ8w0TVU04sOa$350f7f9d5755d5ec9f0ba3b85d3f1808422d208d7c50d3619356645490b96a955c4ece0c896e2831cee0f7dfeab6d13996fdaa1126984897c291e58b6446fb0d', 1733596217, 0, 0, 0, 0, '47a237b8-382a-4885-a9c4-de787d5f85a3', '0'),
('cb54a988-c772-40e4-9c6b-b77e8b6ff4ef', 'Renee', 'Burch', 'erikwoods@example.org', 'scrypt:32768:8:1$jzu0JBlc75nyODek$5e04b1babd50c3a41c93d159047b7527396691bd50ba3d6ff9116f3ce1ba2c4aada4e78831027faa3064a18927ca3be778bd2797fc0aba3104324beb93b4bee9', 1733596217, 0, 0, 0, 1733596217, 'c485efd7-e520-4d34-ae7a-5743fe5bb34d', '0'),
('cba70d47-dbd2-4349-aa8b-f0d52fa3f4e3', 'Matthew', 'Evans', 'katherinedavis@example.com', 'scrypt:32768:8:1$XauA8nPrKjcZ1Xtw$6eb3af3722c6616122d65b59d3b1a8d67f1a4c95aae1e579d682c6791d960b222be64bfbbc43ca1bae1d7e1acd2bed24926a89b93e4f0bccf5f625827e46978b', 1733596217, 0, 0, 0, 0, '030f1b66-c8ed-4b95-a62f-f35b0e965414', '0'),
('d942107e-298c-451f-8db7-8987921a7dbb', 'Luna\'s Tacos & Tequ', '', 'gallegosdavid@example.org', 'scrypt:32768:8:1$CdqSZ8w0TVU04sOa$350f7f9d5755d5ec9f0ba3b85d3f1808422d208d7c50d3619356645490b96a955c4ece0c896e2831cee0f7dfeab6d13996fdaa1126984897c291e58b6446fb0d', 1733596217, 0, 0, 0, 0, '37c2c85d-173f-4de8-92c7-5c43bd9aaf70', '0'),
('eaa2bf24-9bb7-4c5d-9639-99d12e240bb3', 'Victor', 'Taylor', 'westbrian@gmail.com', 'scrypt:32768:8:1$XauA8nPrKjcZ1Xtw$6eb3af3722c6616122d65b59d3b1a8d67f1a4c95aae1e579d682c6791d960b222be64bfbbc43ca1bae1d7e1acd2bed24926a89b93e4f0bccf5f625827e46978b', 1733596217, 0, 0, 0, 0, '2ebee182-54cc-40e4-ad47-c505c1bb6b80', '0'),
('f3e846ca-a01c-410e-9a19-a49bf341b994', 'Austin', 'Shaffer', 'mary04@example.com', 'scrypt:32768:8:1$jzu0JBlc75nyODek$5e04b1babd50c3a41c93d159047b7527396691bd50ba3d6ff9116f3ce1ba2c4aada4e78831027faa3064a18927ca3be778bd2797fc0aba3104324beb93b4bee9', 1733596217, 0, 0, 0, 1733596217, 'c2054dd4-758a-427d-a25d-81f070a22264', '0');

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
('3b1f6532-abf1-4d4f-8d02-61f7890ebed9', '16fd2706-8baf-433b-82eb-8c7fada847da'),
('0060d96a-e7fb-4b73-9ee1-8310ebc329fc', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('02b2a30b-21cd-4cd1-9cf6-d520ee36ef16', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('0b6818c6-a857-4a35-88f1-af8953ec3215', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('0bbfb6f2-1549-452e-ab63-3d719daaaf3f', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('27763272-712a-4d0a-b574-cad7318106a0', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('4007e305-4969-4d61-8e46-fb53e2352ec9', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('61827499-8411-43bf-beaa-6ccf9e50a352', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('87a0fcb1-026e-4c30-9770-002fca5d6929', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('96c21938-1602-44a8-955c-6f710ddddf14', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('c9ef0a32-3595-4729-9762-7c6989bd6427', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('d942107e-298c-451f-8db7-8987921a7dbb', '9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15'),
('048d5f1c-a1e7-4dd7-a40a-250ad162489e', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('081317d3-f0b6-4998-9dbf-ed6b89322f7c', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('1e8047ec-5c9d-4dc0-86d7-2dd8a4fe995d', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('4218788d-03b7-4812-bd7d-31c8859e92d8', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('43246148-3a49-4f46-a340-ffe582f55e43', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('53b58561-bff9-4501-8de4-6c610d443c7a', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('5ee931e9-efa8-4f59-8c1c-4cf3a6ce58b0', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('808dfe5b-44af-4b53-adda-e8a020bcfca0', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('b210a83c-89d3-49e5-9c1a-e15af85f19b3', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('b67caed1-6437-4164-be00-861cb8d664c9', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('c1dfbe76-4b3a-42d5-8049-0f0e274da67e', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('cba70d47-dbd2-4349-aa8b-f0d52fa3f4e3', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('eaa2bf24-9bb7-4c5d-9639-99d12e240bb3', 'c56a4180-65aa-42ec-a945-5fd21dec0538'),
('53570d9b-a9d5-4bfc-858e-c35fda41fb81', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('76a3208e-cdd9-43f0-b490-46075c694e0b', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('76ab0941-b001-4ab5-b20e-fb7da053470c', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('87087305-748e-4bb4-9357-4d9a1dc3e68b', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('8ef6a2e0-5a73-4cc9-a1df-54212fe117c9', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('96e2588c-02f8-4fcb-943f-f2e8899467cb', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('aa8875aa-c937-4d44-9f9a-24d392a1d2ee', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('ab652729-5e74-4379-aa5f-7c643f2b7fdd', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('b38fa0dd-16c2-4fbf-a7c9-8e5956578064', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('cb54a988-c772-40e4-9c6b-b77e8b6ff4ef', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
('f3e846ca-a01c-410e-9a19-a49bf341b994', 'f47ac10b-58cc-4372-a567-0e02b2c3d479');

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
